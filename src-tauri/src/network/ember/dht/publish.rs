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
/// udp_port(2) + buddy noise_pub(32) + callback token(16). HighID records stay
/// 41 bytes. v2 parsers that ignore trailing bytes still accept the contact;
/// this build reads the extra 70 when they are there. Not a version bump.
pub(super) const SOURCE_CALLBACK_TRAILER_LEN: usize = 16 + 4 + 2 + 32 + 16;

fn source_contact_encoded_len(contact: Option<&SourceContact>) -> usize {
    match contact {
        Some(sc) if sc.buddy.is_some() => SOURCE_CONTACT_WIRE_LEN + SOURCE_CALLBACK_TRAILER_LEN,
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
    if let Some(buddy) = sc.buddy {
        data.extend_from_slice(&sc.user_hash.unwrap_or([0u8; 16]));
        data.extend_from_slice(&buddy.ip.octets());
        data.write_u16::<LittleEndian>(buddy.udp_port).unwrap();
        data.extend_from_slice(&buddy.noise_pub);
        data.extend_from_slice(&sc.callback_token.unwrap_or([0u8; 16]));
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
    if data.len() >= rest + SOURCE_CALLBACK_TRAILER_LEN {
        let mut user_hash = [0u8; 16];
        user_hash.copy_from_slice(&data[rest..rest + 16]);
        let b = rest + 16;
        let buddy_ip = Ipv4Addr::new(data[b], data[b + 1], data[b + 2], data[b + 3]);
        let buddy_udp = u16::from_le_bytes([data[b + 4], data[b + 5]]);
        let mut buddy_noise = [0u8; 32];
        buddy_noise.copy_from_slice(&data[b + 6..b + 38]);
        let mut token = [0u8; 16];
        token.copy_from_slice(&data[b + 38..b + 54]);
        if buddy_udp != 0 && !buddy_ip.is_unspecified() {
            contact.user_hash = (user_hash != [0u8; 16]).then_some(user_hash);
            contact.buddy = Some(SourceBuddy {
                ip: buddy_ip,
                udp_port: buddy_udp,
                noise_pub: buddy_noise,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceBuddy {
    pub ip: Ipv4Addr,
    pub udp_port: u16,
    pub noise_pub: [u8; 32],
}

impl SourceBuddy {
    /// Whether this buddy is a plausible UDP destination for `CALLBACK_REQ`.
    /// Special-use / unspecified IPv4 and port 0 never are.
    pub fn is_routable(&self) -> bool {
        self.udp_port != 0
            && !self.ip.is_unspecified()
            && !crate::security::is_special_use_v4(self.ip)
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
    /// publisher id, or an unusable buddy all return false — the caller then
    /// falls back to the firewalled EPX park path rather than dropping the
    /// source or TCP-dialling the unverified NAT address.
    pub fn takes_callback(&self, searcher_tcp_firewalled: bool) -> bool {
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
        self.buddy.is_some_and(|b| b.is_routable())
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

    fn test_buddy() -> SourceBuddy {
        SourceBuddy {
            ip: Ipv4Addr::new(8, 8, 4, 4),
            udp_port: 4672,
            noise_pub: [0xB1; 32],
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
            udp_port: 4672,
            noise_pub: [0xB1; 32],
        }
        .is_routable());
        assert!(!SourceBuddy {
            ip: Ipv4Addr::new(8, 8, 4, 4),
            udp_port: 0,
            noise_pub: [0xB1; 32],
        }
        .is_routable());
        assert!(
            !SourceBuddy {
                ip: Ipv4Addr::new(203, 0, 113, 10),
                udp_port: 4672,
                noise_pub: [0xB1; 32],
            }
            .is_routable(),
            "TEST-NET documentation addresses are not callback destinations"
        );
    }

    #[test]
    fn takes_callback_requires_a_reachable_searcher_and_a_usable_buddy() {
        let src = discovered_firewalled(Some(test_buddy()));
        assert!(src.takes_callback(false));
        assert!(
            !src.takes_callback(true),
            "a firewalled searcher must park, not CALLBACK_REQ"
        );

        let highid = DiscoveredSource {
            flags: 0,
            ..src
        };
        assert!(!highid.takes_callback(false));

        let no_id = DiscoveredSource {
            publisher_id: [0u8; 16],
            ..src
        };
        assert!(!no_id.takes_callback(false));

        let lan_buddy = discovered_firewalled(Some(SourceBuddy {
            ip: Ipv4Addr::new(192, 168, 1, 1),
            udp_port: 4672,
            noise_pub: [0xB1; 32],
        }));
        assert!(
            !lan_buddy.takes_callback(false),
            "unusable buddy must not take the callback path (park instead)"
        );

        let no_buddy = discovered_firewalled(None);
        assert!(!no_buddy.takes_callback(false));

        let no_token = DiscoveredSource {
            callback_token: None,
            ..src
        };
        assert!(!no_token.takes_callback(false));
    }
}
