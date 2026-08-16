use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use byteorder::{LittleEndian, WriteBytesExt};
use ed25519_dalek::SigningKey;
use tracing::{debug, trace, warn};

use super::routing::RoutingTable;
use super::search::keyword_hash;
use super::{EmberContact, EmberNodeId, K_BUCKET_SIZE};
use crate::network::ember::channel;
use crate::network::ember::crypto;

/// Maximum concurrent publish operations.
const MAX_ACTIVE_PUBLISHES: usize = 128;

/// How long to wait for a STORE_ACK before timing out.
const PUBLISH_TIMEOUT_SECS: u64 = 30;

/// Minimum number of nodes to store a record on.
const MIN_STORE_NODES: usize = 5;

/// Record type constants.
pub const RECORD_TYPE_KEYWORD: u8 = 0x01;
pub const RECORD_TYPE_SOURCE: u8 = 0x02;
/// Channel index, presence, or moderation metadata. Never carries an IP.
pub const RECORD_TYPE_CHANNEL: u8 = 0x03;

pub const CHANNEL_KIND_INDEX: u8 = 1;
pub const CHANNEL_KIND_PRESENCE: u8 = 2;
pub const CHANNEL_KIND_MODERATION: u8 = 3;
pub const CHANNEL_FLAG_PRIVATE: u8 = 0x01;
const CHANNEL_TRAILER_VERSION: u8 = 1;
/// `version(1) + extra_len(2)` before the variable extra blob.
const CHANNEL_TRAILER_MIN_LEN: usize = 1 + 2;
pub const CHANNEL_NAME_MAX: usize = 64;
pub const CHANNEL_WELCOME_MAX: usize = 512;
pub const CHANNEL_BAN_LIST_MAX: usize = 32;
pub const CHANNEL_MOD_LIST_MAX: usize = 16;

/// Wire size of the trailing contact block a source record appends after
/// its file name: ip(4) + tcp_port(2) + udp_port(2) + flags(1) + noise_pub(32).
pub(super) const SOURCE_CONTACT_WIRE_LEN: usize = 4 + 2 + 2 + 1 + 32;

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

/// The publisher's self-reported reachable contact, carried inside a
/// signed `RECORD_TYPE_SOURCE` record (and therefore covered by the
/// publisher's signature). A downloader uses `ip` + `tcp_port` to dial the
/// source over the existing eD2K client-to-client path; `noise_pub` is
/// stashed for future native (Noise) dialing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceContact {
    pub ip: Ipv4Addr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub flags: u8,
    pub noise_pub: [u8; 32],
}

/// Channel-specific trailer parsed from a `RECORD_TYPE_CHANNEL` body.
///
/// `kind`/`flags` are also packed into `file_size` so the store can pick a
/// TTL without walking the variable-length name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRecordMeta {
    pub kind: u8,
    pub flags: u8,
    pub extra: Vec<u8>,
}

impl ChannelRecordMeta {
    pub fn is_private(&self) -> bool {
        self.flags & CHANNEL_FLAG_PRIVATE != 0
    }
}

/// A member announced under a channel presence key. No address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPresenceMember {
    pub publisher_key: [u8; 32],
    pub nickname: String,
    pub timestamp: i64,
    pub noise_pub: [u8; 32],
}

/// Owner-signed topic, welcome, ban list, and delegated moderators. No addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelModeration {
    pub topic: String,
    pub welcome: String,
    pub banned_pubkeys: Vec<[u8; 32]>,
    pub moderator_pubkeys: Vec<[u8; 32]>,
    pub timestamp: i64,
    pub publisher_key: [u8; 32],
}

pub fn pack_channel_file_size(kind: u8, flags: u8) -> u64 {
    u64::from(kind) | (u64::from(flags) << 8)
}

pub fn channel_kind_from_data(data: &[u8]) -> Option<u8> {
    // `file_size` sits at offset 65 in the fixed header and is little-endian,
    // so the low byte — the kind — is `data[65]`.
    if data.first() == Some(&RECORD_TYPE_CHANNEL) {
        data.get(65).copied()
    } else {
        None
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
    /// Present only for `RECORD_TYPE_CHANNEL`.
    pub channel: Option<ChannelRecordMeta>,
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
            None,
            signing_key,
        )
    }

    /// Public/private index listing, signed by the **channel** key.
    pub fn channel_index(
        name: &str,
        channel_id: [u8; 16],
        channel_pubkey: [u8; 32],
        private: bool,
        signing_key: &SigningKey,
    ) -> Self {
        let flags = if private { CHANNEL_FLAG_PRIVATE } else { 0 };
        let name = truncate_utf8(name, CHANNEL_NAME_MAX);
        Self::build(
            RECORD_TYPE_CHANNEL,
            channel::index_key_for_channel(&channel_id),
            channel_id,
            channel_pubkey,
            pack_channel_file_size(CHANNEL_KIND_INDEX, flags),
            name,
            None,
            Some(Vec::new()),
            signing_key,
        )
    }

    /// Membership presence: pubkey + nickname + Noise static key, never an
    /// address. Signed by the **member**, with the channel pubkey in
    /// `ember_file_hash`. `noise_pub` lets XOR-neighbors start Noise_IK
    /// after a rendezvous lookup without publishing an IP.
    pub fn channel_presence(
        nickname: &str,
        channel_id: [u8; 16],
        channel_pubkey: [u8; 32],
        join_secret: &[u8; 32],
        private: bool,
        epoch: i64,
        noise_pub: &[u8; 32],
        signing_key: &SigningKey,
    ) -> Self {
        let flags = if private { CHANNEL_FLAG_PRIVATE } else { 0 };
        let (nickname, extra) = channel::encode_presence_extra(
            private,
            &channel::content_key(join_secret),
            &channel_id,
            noise_pub,
            nickname,
        );
        Self::build(
            RECORD_TYPE_CHANNEL,
            channel::presence_key(&channel_id, join_secret, epoch),
            channel_id,
            channel_pubkey,
            pack_channel_file_size(CHANNEL_KIND_PRESENCE, flags),
            &nickname,
            None,
            Some(extra),
            signing_key,
        )
    }

    /// Moderation record signed by the **channel** key: topic, welcome, bans, mods.
    pub fn channel_moderation(
        topic: &str,
        welcome: &str,
        banned_pubkeys: &[[u8; 32]],
        moderator_pubkeys: &[[u8; 32]],
        channel_id: [u8; 16],
        channel_pubkey: [u8; 32],
        private: bool,
        signing_key: &SigningKey,
    ) -> Self {
        let flags = if private { CHANNEL_FLAG_PRIVATE } else { 0 };
        let topic = truncate_utf8(topic, CHANNEL_NAME_MAX);
        let extra = encode_moderation_extra(welcome, banned_pubkeys, moderator_pubkeys);
        Self::build(
            RECORD_TYPE_CHANNEL,
            channel::moderation_key(&channel_id),
            channel_id,
            channel_pubkey,
            pack_channel_file_size(CHANNEL_KIND_MODERATION, flags),
            topic,
            None,
            Some(extra),
            signing_key,
        )
    }

    /// Whether a STORE of this channel record is well-formed enough to keep.
    ///
    /// Storers cannot check a private presence key (it folds in `join_secret`),
    /// but they can refuse a record whose channel_id does not match the
    /// claimed channel pubkey, an index/moderation record not signed by that
    /// key, or an index filed under the wrong shard.
    pub fn channel_store_ok(&self) -> bool {
        if self.record_type != RECORD_TYPE_CHANNEL {
            return false;
        }
        let Some(meta) = &self.channel else {
            return false;
        };
        let Some(expected_id) = crypto::node_id_from_ed25519_bytes(&self.ember_file_hash) else {
            return false;
        };
        if self.file_hash != expected_id {
            return false;
        }
        match meta.kind {
            CHANNEL_KIND_INDEX => {
                self.publisher_key == self.ember_file_hash
                    && self.keyword_hash == channel::index_key_for_channel(&self.file_hash)
            }
            CHANNEL_KIND_PRESENCE => {
                crypto::verifying_key_from_bytes(&self.publisher_key).is_some()
                    && channel::presence_extra_store_ok(&meta.extra)
            }
            CHANNEL_KIND_MODERATION => {
                self.publisher_key == self.ember_file_hash
                    && self.keyword_hash == channel::moderation_key(&self.file_hash)
            }
            _ => false,
        }
    }

    fn build(
        record_type: u8,
        keyword_hash: [u8; 16],
        file_hash: [u8; 16],
        ember_file_hash: [u8; 32],
        file_size: u64,
        file_name: &str,
        source_contact: Option<SourceContact>,
        channel_extra: Option<Vec<u8>>,
        signing_key: &SigningKey,
    ) -> Self {
        let publisher_key = signing_key.verifying_key().to_bytes();
        let timestamp = chrono::Utc::now().timestamp();
        let name_bytes = file_name.as_bytes();
        let name_len = name_bytes.len().min(u16::MAX as usize);

        let mut data = Vec::with_capacity(
            1 + 16 + 16 + 32 + 8 + 32 + 8 + 2 + name_len + SOURCE_CONTACT_WIRE_LEN,
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
            data.extend_from_slice(&sc.ip.octets());
            data.write_u16::<LittleEndian>(sc.tcp_port).unwrap();
            data.write_u16::<LittleEndian>(sc.udp_port).unwrap();
            data.push(sc.flags);
            data.extend_from_slice(&sc.noise_pub);
        }

        let channel = if let Some(extra) = channel_extra {
            let extra_len = extra.len().min(u16::MAX as usize);
            data.push(CHANNEL_TRAILER_VERSION);
            data.write_u16::<LittleEndian>(extra_len as u16).unwrap();
            data.extend_from_slice(&extra[..extra_len]);
            Some(ChannelRecordMeta {
                kind: (file_size & 0xff) as u8,
                flags: ((file_size >> 8) & 0xff) as u8,
                extra: extra[..extra_len].to_vec(),
            })
        } else {
            None
        };

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
            channel,
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

    /// Parse a channel presence blob into the member's identity. IPs never
    /// appear here; `noise_pub` is the Ember UDP static key for a later
    /// Noise_IK handshake after rendezvous supplies an address.
    pub fn parse_channel_presence_member(
        blob: &[u8],
        expected_channel_id: &[u8; 16],
        content_key: Option<&[u8; 32]>,
    ) -> Option<ChannelPresenceMember> {
        let rec = Self::from_value_blob(blob)?;
        if rec.record_type != RECORD_TYPE_CHANNEL || rec.file_hash != *expected_channel_id {
            return None;
        }
        if !rec.channel_store_ok() {
            return None;
        }
        let meta = rec.channel.as_ref()?;
        if meta.kind != CHANNEL_KIND_PRESENCE {
            return None;
        }
        let (noise_pub, nickname) = channel::decode_presence_extra(
            content_key,
            expected_channel_id,
            &meta.extra,
            &rec.file_name,
        )?;
        Some(ChannelPresenceMember {
            publisher_key: rec.publisher_key,
            nickname,
            timestamp: rec.timestamp,
            noise_pub,
        })
    }

    /// Parse an owner-signed moderation blob. Topic lives in `file_name`;
    /// welcome and the ban list are in the trailer extra.
    pub fn parse_channel_moderation(
        blob: &[u8],
        expected_channel_id: &[u8; 16],
    ) -> Option<ChannelModeration> {
        let rec = Self::from_value_blob(blob)?;
        if rec.record_type != RECORD_TYPE_CHANNEL || rec.file_hash != *expected_channel_id {
            return None;
        }
        if !rec.channel_store_ok() {
            return None;
        }
        let meta = rec.channel.as_ref()?;
        if meta.kind != CHANNEL_KIND_MODERATION {
            return None;
        }
        let (welcome, banned_pubkeys, moderator_pubkeys) = decode_moderation_extra(&meta.extra)?;
        Some(ChannelModeration {
            topic: rec.file_name,
            welcome,
            banned_pubkeys,
            moderator_pubkeys,
            timestamp: rec.timestamp,
            publisher_key: rec.publisher_key,
        })
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
        if data[0] == RECORD_TYPE_CHANNEL
            && !channel_trailer_len(data, name_len)
                .is_some_and(|n| data.len() == 115 + name_len + n)
        {
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
            if data.len() < off + SOURCE_CONTACT_WIRE_LEN {
                return None;
            }
            let ip = Ipv4Addr::new(data[off], data[off + 1], data[off + 2], data[off + 3]);
            let tcp_port = u16::from_le_bytes([data[off + 4], data[off + 5]]);
            let udp_port = u16::from_le_bytes([data[off + 6], data[off + 7]]);
            let flags = data[off + 8];
            let mut noise_pub = [0u8; 32];
            noise_pub.copy_from_slice(&data[off + 9..off + 41]);
            Some(SourceContact {
                ip,
                tcp_port,
                udp_port,
                flags,
                noise_pub,
            })
        } else {
            None
        };

        let channel = if record_type == RECORD_TYPE_CHANNEL {
            let off = 115 + name_len;
            let trailer_len = channel_trailer_len(data, name_len)?;
            if data.len() != off + trailer_len {
                return None;
            }
            if data[off] != CHANNEL_TRAILER_VERSION {
                return None;
            }
            let extra_len = u16::from_le_bytes([data[off + 1], data[off + 2]]) as usize;
            Some(ChannelRecordMeta {
                kind: (file_size & 0xff) as u8,
                flags: ((file_size >> 8) & 0xff) as u8,
                extra: data[off + 3..off + 3 + extra_len].to_vec(),
            })
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
            channel,
        })
    }
}

fn channel_trailer_len(data: &[u8], name_len: usize) -> Option<usize> {
    let off = 115 + name_len;
    if data.len() < off + CHANNEL_TRAILER_MIN_LEN {
        return None;
    }
    let extra_len = u16::from_le_bytes([data[off + 1], data[off + 2]]) as usize;
    Some(CHANNEL_TRAILER_MIN_LEN + extra_len)
}

fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn encode_moderation_extra(
    welcome: &str,
    banned_pubkeys: &[[u8; 32]],
    moderator_pubkeys: &[[u8; 32]],
) -> Vec<u8> {
    let welcome = truncate_utf8(welcome, CHANNEL_WELCOME_MAX);
    let bans = banned_pubkeys
        .iter()
        .take(CHANNEL_BAN_LIST_MAX)
        .collect::<Vec<_>>();
    let mods = moderator_pubkeys
        .iter()
        .take(CHANNEL_MOD_LIST_MAX)
        .collect::<Vec<_>>();
    let mut extra =
        Vec::with_capacity(2 + welcome.len() + 2 + bans.len() * 32 + 2 + mods.len() * 32);
    extra.extend_from_slice(&(welcome.len() as u16).to_le_bytes());
    extra.extend_from_slice(welcome.as_bytes());
    extra.extend_from_slice(&(bans.len() as u16).to_le_bytes());
    for pk in bans {
        extra.extend_from_slice(pk);
    }
    extra.extend_from_slice(&(mods.len() as u16).to_le_bytes());
    for pk in mods {
        extra.extend_from_slice(pk);
    }
    extra
}

/// Decode the extra blob from a moderation record.
///
/// Records published before moderator delegations omit the trailing list;
/// treat that as an empty delegation set so a mixed network can still apply
/// topic/welcome/bans.
pub fn decode_moderation_extra(extra: &[u8]) -> Option<(String, Vec<[u8; 32]>, Vec<[u8; 32]>)> {
    if extra.len() < 4 {
        return None;
    }
    let welcome_len = u16::from_le_bytes([extra[0], extra[1]]) as usize;
    if extra.len() < 2 + welcome_len + 2 {
        return None;
    }
    let welcome = String::from_utf8(extra[2..2 + welcome_len].to_vec()).ok()?;
    let ban_off = 2 + welcome_len;
    let ban_count = u16::from_le_bytes([extra[ban_off], extra[ban_off + 1]]) as usize;
    if ban_count > CHANNEL_BAN_LIST_MAX {
        return None;
    }
    let bans_end = ban_off + 2 + ban_count * 32;
    if extra.len() < bans_end {
        return None;
    }
    let mut bans = Vec::with_capacity(ban_count);
    for chunk in extra[ban_off + 2..bans_end].chunks_exact(32) {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(chunk);
        bans.push(pk);
    }
    let rest = &extra[bans_end..];
    if rest.is_empty() {
        return Some((welcome, bans, Vec::new()));
    }
    if rest.len() < 2 {
        return None;
    }
    let mod_count = u16::from_le_bytes([rest[0], rest[1]]) as usize;
    if mod_count > CHANNEL_MOD_LIST_MAX {
        return None;
    }
    let mods_bytes = &rest[2..];
    if mods_bytes.len() != mod_count * 32 {
        return None;
    }
    let mut mods = Vec::with_capacity(mod_count);
    for chunk in mods_bytes.chunks_exact(32) {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(chunk);
        mods.push(pk);
    }
    Some((welcome, bans, mods))
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

    /// Start publishing a signed record. First finds the closest nodes to the key,
    /// then stores on them.
    /// Returns `None` when the active-publish cap is reached so the
    /// caller can surface a "busy" state instead of unbounded growth.
    pub fn start_publish(
        &mut self,
        record: SignedRecord,
        routing_table: &RoutingTable,
    ) -> Option<u32> {
        if self.operations.len() >= MAX_ACTIVE_PUBLISHES {
            warn!(
                "Too many active publishes ({}), rejecting new publish",
                self.operations.len()
            );
            return None;
        }

        let dht_key = EmberNodeId(record.keyword_hash);
        let targets = routing_table.find_closest_prefer_verified(&dht_key, K_BUCKET_SIZE);

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
        let pub_id = pm.start_publish(record, &rt).expect("publish slot");

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
    fn channel_index_round_trip_and_store_ok() {
        let ident = channel::ChannelIdentity::generate();
        let record = SignedRecord::channel_index(
            "Lobby",
            ident.channel_id,
            ident.pubkey,
            false,
            &ident.signing_key,
        );
        assert_eq!(record.record_type, RECORD_TYPE_CHANNEL);
        assert_eq!(
            record.keyword_hash,
            channel::index_key_for_channel(&ident.channel_id)
        );
        assert!(record.channel_store_ok());
        assert_eq!(record.channel.as_ref().unwrap().kind, CHANNEL_KIND_INDEX);
        assert!(!record.channel.as_ref().unwrap().is_private());

        let parsed = SignedRecord::from_wire(&record.data, record.signature).unwrap();
        assert_eq!(parsed.file_name, "Lobby");
        assert_eq!(parsed.file_hash, ident.channel_id);
        assert!(parsed.channel_store_ok());
        let mut blob = record.data.clone();
        blob.extend_from_slice(&record.signature);
        assert!(SignedRecord::value_blob_is_authentic(&blob));
    }

    #[test]
    fn channel_index_rejects_wrong_shard() {
        let ident = channel::ChannelIdentity::generate();
        let mut record = SignedRecord::channel_index(
            "Lobby",
            ident.channel_id,
            ident.pubkey,
            false,
            &ident.signing_key,
        );
        record.keyword_hash = channel::index_key(index_other_shard(&ident.channel_id));
        assert!(!record.channel_store_ok());
    }

    fn index_other_shard(channel_id: &[u8; 16]) -> u8 {
        (channel::index_shard(channel_id) + 1) % channel::INDEX_SHARD_COUNT
    }

    #[test]
    fn channel_presence_is_signed_by_member_not_channel() {
        let channel = channel::ChannelIdentity::generate();
        let member = SigningKey::generate(&mut OsRng);
        let join = channel::public_join_secret(&channel.pubkey);
        let noise_pub = [0x42u8; 32];
        let mut record = SignedRecord::channel_presence(
            "Ada",
            channel.channel_id,
            channel.pubkey,
            &join,
            false,
            3,
            &noise_pub,
            &member,
        );
        assert_eq!(record.publisher_key, member.verifying_key().to_bytes());
        assert_ne!(record.publisher_key, channel.pubkey);
        assert!(record.channel_store_ok());
        assert_eq!(
            record.keyword_hash,
            channel::presence_key(&channel.channel_id, &join, 3)
        );
        let parsed = SignedRecord::from_wire(&record.data, record.signature).unwrap();
        assert_eq!(parsed.file_name, "Ada");
        assert_eq!(parsed.channel.as_ref().unwrap().kind, CHANNEL_KIND_PRESENCE);
        assert_eq!(parsed.channel.as_ref().unwrap().extra, noise_pub);
        assert!(parsed.source_contact.is_none());

        let mut blob = record.data.clone();
        blob.extend_from_slice(&record.signature);
        let member_info =
            SignedRecord::parse_channel_presence_member(&blob, &channel.channel_id, None).unwrap();
        assert_eq!(member_info.publisher_key, member.verifying_key().to_bytes());
        assert_eq!(member_info.nickname, "Ada");
        assert_eq!(member_info.noise_pub, noise_pub);
        assert!(SignedRecord::parse_channel_presence_member(&blob, &[0x00; 16], None).is_none());
        record.channel.as_mut().unwrap().extra.clear();
        assert!(!record.channel_store_ok());
    }

    #[test]
    fn private_channel_presence_extra_is_encrypted() {
        let channel = channel::ChannelIdentity::generate();
        let member = SigningKey::generate(&mut OsRng);
        let join = [0x77u8; 32];
        let noise_pub = [0x42u8; 32];
        let record = SignedRecord::channel_presence(
            "Ada",
            channel.channel_id,
            channel.pubkey,
            &join,
            true,
            3,
            &noise_pub,
            &member,
        );
        assert!(record.channel_store_ok());
        assert!(record.file_name.is_empty());
        assert_ne!(record.channel.as_ref().unwrap().extra, noise_pub);
        let mut blob = record.data.clone();
        blob.extend_from_slice(&record.signature);
        assert!(
            SignedRecord::parse_channel_presence_member(&blob, &channel.channel_id, None).is_none()
        );
        let key = channel::content_key(&join);
        let member_info =
            SignedRecord::parse_channel_presence_member(&blob, &channel.channel_id, Some(&key))
                .unwrap();
        assert_eq!(member_info.nickname, "Ada");
        assert_eq!(member_info.noise_pub, noise_pub);
    }

    #[test]
    fn channel_moderation_round_trip() {
        let ident = channel::ChannelIdentity::generate();
        let banned = [[0x11u8; 32], [0x22u8; 32]];
        let mods = [[0xAAu8; 32]];
        let record = SignedRecord::channel_moderation(
            "rules",
            "be kind",
            &banned,
            &mods,
            ident.channel_id,
            ident.pubkey,
            false,
            &ident.signing_key,
        );
        assert!(record.channel_store_ok());
        let parsed = SignedRecord::from_wire(&record.data, record.signature).unwrap();
        let (welcome, bans, parsed_mods) =
            decode_moderation_extra(&parsed.channel.unwrap().extra).unwrap();
        assert_eq!(parsed.file_name, "rules");
        assert_eq!(welcome, "be kind");
        assert_eq!(bans, banned);
        assert_eq!(parsed_mods, mods);

        let mut blob = record.data.clone();
        blob.extend_from_slice(&record.signature);
        let mod_info = SignedRecord::parse_channel_moderation(&blob, &ident.channel_id).unwrap();
        assert_eq!(mod_info.topic, "rules");
        assert_eq!(mod_info.welcome, "be kind");
        assert_eq!(mod_info.banned_pubkeys, banned);
        assert_eq!(mod_info.moderator_pubkeys, mods);
        assert_eq!(mod_info.publisher_key, ident.pubkey);
        assert!(SignedRecord::parse_channel_moderation(&blob, &[0x00; 16]).is_none());

        // Pre-delegation extra: welcome + bans and nothing after.
        let mut legacy = encode_moderation_extra("hi", &banned, &[]);
        legacy.truncate(legacy.len() - 2);
        let (w, b, m) = decode_moderation_extra(&legacy).unwrap();
        assert_eq!(w, "hi");
        assert_eq!(b, banned);
        assert!(m.is_empty());
    }

    #[test]
    fn truncated_channel_trailer_is_rejected() {
        let ident = channel::ChannelIdentity::generate();
        let record = SignedRecord::channel_index(
            "x",
            ident.channel_id,
            ident.pubkey,
            false,
            &ident.signing_key,
        );
        let truncated = &record.data[..record.data.len() - 1];
        assert!(SignedRecord::from_wire(truncated, record.signature).is_none());
        let mut blob = truncated.to_vec();
        blob.extend_from_slice(&record.signature);
        assert!(!SignedRecord::value_blob_is_authentic(&blob));
    }

    #[test]
    fn decode_moderation_extra_fuzz_never_panics() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC8A1_E07A);
        let well_formed =
            encode_moderation_extra("welcome ☕", &[[0x11u8; 32], [0x22u8; 32]], &[[0xAAu8; 32]]);
        let mut legacy = encode_moderation_extra("hi", &[[0x11u8; 32]], &[]);
        legacy.truncate(legacy.len() - 2);
        let mut decoded_ok = 0usize;
        for i in 0..2_000 {
            let extra = match i {
                0 => well_formed.clone(),
                1 => legacy.clone(),
                _ => {
                    let len = rng.gen_range(0..=800);
                    let mut buf = vec![0u8; len];
                    rng.fill(&mut buf[..]);
                    if i % 19 == 0 {
                        buf = well_formed.clone();
                        let at = rng.gen_range(0..buf.len());
                        buf[at] ^= rng.gen_range(1u8..=255);
                    }
                    buf
                }
            };
            if decode_moderation_extra(&extra).is_some() {
                decoded_ok += 1;
            }
        }
        let (welcome, bans, mods) = decode_moderation_extra(&well_formed).unwrap();
        assert_eq!(welcome, "welcome ☕");
        assert_eq!(bans.len(), 2);
        assert_eq!(mods.len(), 1);
        assert!(
            decoded_ok > 0,
            "the fuzz never produced a buffer that reached decode_moderation_extra"
        );
    }

    #[test]
    fn channel_record_parse_fuzz_never_panics() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC8A1_51C6);
        let ident = channel::ChannelIdentity::generate();
        let member = SigningKey::generate(&mut OsRng);
        let join = channel::public_join_secret(&ident.pubkey);
        let presence = SignedRecord::channel_presence(
            "Ada",
            ident.channel_id,
            ident.pubkey,
            &join,
            false,
            3,
            &[0x42u8; 32],
            &member,
        );
        let moderation = SignedRecord::channel_moderation(
            "rules",
            "be kind",
            &[[0x11u8; 32]],
            &[[0xAAu8; 32]],
            ident.channel_id,
            ident.pubkey,
            false,
            &ident.signing_key,
        );
        let mut presence_blob = presence.data.clone();
        presence_blob.extend_from_slice(&presence.signature);
        let mut moderation_blob = moderation.data.clone();
        moderation_blob.extend_from_slice(&moderation.signature);
        let mut parsed_ok = 0usize;
        for i in 0..2_000 {
            let buf = match i {
                0 => presence_blob.clone(),
                1 => moderation_blob.clone(),
                _ => {
                    let len = rng.gen_range(0..=1_200);
                    let mut buf = vec![0u8; len];
                    rng.fill(&mut buf[..]);
                    if i % 21 == 0 {
                        buf = if i % 2 == 0 {
                            presence_blob.clone()
                        } else {
                            moderation_blob.clone()
                        };
                        let at = rng.gen_range(0..buf.len());
                        buf[at] ^= rng.gen_range(1u8..=255);
                    }
                    buf
                }
            };
            let _ = SignedRecord::from_value_blob(&buf);
            let _ = SignedRecord::value_blob_is_authentic(&buf);
            if SignedRecord::parse_channel_presence_member(&buf, &ident.channel_id, None).is_some()
            {
                parsed_ok += 1;
            }
            if SignedRecord::parse_channel_moderation(&buf, &ident.channel_id).is_some() {
                parsed_ok += 1;
            }
            let _ = SignedRecord::parse_channel_presence_member(&buf, &[0u8; 16], None);
            let _ = SignedRecord::parse_channel_moderation(&buf, &[0u8; 16]);
        }
        assert!(SignedRecord::parse_channel_presence_member(
            &presence_blob,
            &ident.channel_id,
            None
        )
        .is_some());
        assert!(
            SignedRecord::parse_channel_moderation(&moderation_blob, &ident.channel_id).is_some()
        );
        assert!(
            parsed_ok > 0,
            "the fuzz never produced a buffer that reached the channel record parsers"
        );
    }
}
