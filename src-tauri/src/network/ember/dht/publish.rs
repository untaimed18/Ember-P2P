use std::collections::HashMap;
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
            signing_key,
        )
    }

    /// Create a source record: announces that we are a source for a file.
    pub fn source(
        file_hash: [u8; 16],
        ember_file_hash: [u8; 32],
        file_size: u64,
        file_name: &str,
        signing_key: &SigningKey,
    ) -> Self {
        let file_key = {
            let hash = blake3::hash(&file_hash);
            let mut key = [0u8; 16];
            key.copy_from_slice(&hash.as_bytes()[..16]);
            key
        };
        Self::build(
            RECORD_TYPE_SOURCE,
            file_key,
            file_hash,
            ember_file_hash,
            file_size,
            file_name,
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
        signing_key: &SigningKey,
    ) -> Self {
        let publisher_key = signing_key.verifying_key().to_bytes();
        let timestamp = chrono::Utc::now().timestamp();
        let name_bytes = file_name.as_bytes();

        let mut data = Vec::with_capacity(1 + 16 + 16 + 32 + 8 + 32 + 8 + 2 + name_bytes.len());
        data.push(record_type);
        data.extend_from_slice(&keyword_hash);
        data.extend_from_slice(&file_hash);
        data.extend_from_slice(&ember_file_hash);
        data.write_u64::<LittleEndian>(file_size).unwrap();
        data.extend_from_slice(&publisher_key);
        data.write_i64::<LittleEndian>(timestamp).unwrap();
        data.write_u16::<LittleEndian>(name_bytes.len().min(u16::MAX as usize) as u16)
            .unwrap();
        data.extend_from_slice(&name_bytes[..name_bytes.len().min(u16::MAX as usize)]);

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
        }
    }

    /// Get targets that haven't been sent to yet.
    pub fn next_to_store(&mut self) -> Vec<(EmberContact, u32)> {
        let mut batch = Vec::new();
        for target in &self.targets {
            if self.acked.contains(&target.node_id)
                || self.failed.contains(&target.node_id)
                || self.pending_requests.values().any(|id| *id == target.node_id)
            {
                continue;
            }
            let req_id = rand::random::<u32>();
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
    pub fn start_publish(
        &mut self,
        record: SignedRecord,
        routing_table: &RoutingTable,
    ) -> u32 {
        if self.operations.len() >= MAX_ACTIVE_PUBLISHES {
            warn!(
                "Too many active publishes ({}), oldest will be overwritten",
                self.operations.len()
            );
        }

        let dht_key = EmberNodeId(record.keyword_hash);
        let targets = routing_table.find_closest(&dht_key, K_BUCKET_SIZE);

        if targets.len() < MIN_STORE_NODES {
            debug!(
                "Only {} targets for publish (need {MIN_STORE_NODES}), publishing anyway",
                targets.len()
            );
        }

        let id = self.alloc_id();
        let op = PublishOperation::new(id, record, targets);
        trace!(
            "Starting publish {} on {} nodes for key {}",
            id,
            op.targets.len(),
            op.dht_key
        );
        self.operations.insert(id, op);
        id
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

    fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
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
        let record = SignedRecord::keyword(
            "test",
            [1u8; 16],
            [2u8; 32],
            12345,
            "test_file.txt",
            &sk,
        );

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

    #[test]
    fn signed_source_record_round_trip() {
        let sk = SigningKey::generate(&mut OsRng);
        let record = SignedRecord::source(
            [0xAA; 16],
            [0xBB; 32],
            99999,
            "source_file.mp3",
            &sk,
        );

        assert!(record.verify());
        assert_eq!(record.record_type, RECORD_TYPE_SOURCE);
    }

    #[test]
    fn tampered_record_fails_verification() {
        let sk = SigningKey::generate(&mut OsRng);
        let record = SignedRecord::keyword(
            "test",
            [1u8; 16],
            [2u8; 32],
            12345,
            "test_file.txt",
            &sk,
        );

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
        let pub_id = pm.start_publish(record, &rt);

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
