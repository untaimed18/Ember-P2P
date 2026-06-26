use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use byteorder::{LittleEndian, WriteBytesExt};
use ed25519_dalek::SigningKey;
use tracing::{debug, trace, warn};

use super::routing::RoutingTable;
use super::search::keyword_hash;
use super::{EmberContact, EmberNodeId, K_BUCKET_SIZE};
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

/// Wire size of the trailing contact block a source record appends after
/// its file name: ip(4) + tcp_port(2) + udp_port(2) + flags(1) + noise_pub(32).
const SOURCE_CONTACT_WIRE_LEN: usize = 4 + 2 + 2 + 1 + 32;

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
        let targets = routing_table.find_closest(&dht_key, K_BUCKET_SIZE);

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
        let mut rt = RoutingTable::new(local);

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
}
