//! Ember DHT engine: the glue between the signed DHT wire protocol
//! ([`super::messages`]) and the Kademlia routing table
//! ([`super::routing`]).
//!
//! This is the first slice that makes the scaffolded Ember DHT *do*
//! something: it owns our Ed25519 signing identity, derives our
//! 128-bit node ID, holds the routing table, and turns an inbound
//! decrypted DHT frame into (a) routing-table updates and (b) signed
//! response frames for the caller to encrypt and send.
//!
//! It is deliberately transport-agnostic and IO-free: the network task
//! feeds it already-decrypted payloads (Noise has run by then) and
//! ships whatever frames it returns back over [`super::super::transport`].
//! That keeps the protocol logic unit-testable without a live socket or
//! a `NetworkState`.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use tracing::trace;

use super::messages::{self, DhtPayload};
use super::publish::{SignedRecord, SourceContact, RECORD_TYPE_SOURCE};
use super::routing::{AddResult, RoutingTable};
use super::store::DhtStore;
use super::{EmberContact, EmberNodeId, ID_BITS, K_BUCKET_SIZE, MAX_CONTACTS_PER_RESPONSE};
use crate::network::ember::crypto;

/// What the engine produced from one inbound DHT frame.
#[derive(Default)]
pub struct DhtInbound {
    /// Signed DHT frames to encrypt and send back to the sender
    /// (e.g. a `PONG` answering a `PING`, or a `FOUND_NODE` answering a
    /// `FIND_NODE`). Already wire-encoded.
    pub responses: Vec<Vec<u8>>,
    /// The frame was a `PING` we answered.
    pub ping_received: bool,
    /// The frame was a `PONG`.
    pub pong_received: bool,
    /// For a `PONG`, the `request_id` it answered (so the caller can
    /// resolve a pending-ping waiter and compute RTT).
    pub pong_request_id: Option<u32>,
    /// The frame was a `FIND_NODE` we answered with a `FOUND_NODE`.
    pub find_node_received: bool,
    /// For a `FOUND_NODE`, the `request_id` it answered plus the
    /// contacts it carried (so the caller can resolve a pending
    /// find-node waiter). The contacts are also merged into the
    /// routing table before this is returned.
    pub found_node: Option<(u32, Vec<EmberContact>)>,
    /// The verified node ID of the frame's sender (present whenever the
    /// frame decoded — the signature/identity binding has passed). The
    /// caller uses it to correlate a `FOUND_NODE` against an in-flight
    /// iterative-lookup query.
    pub sender_id: Option<EmberNodeId>,
    /// The frame was a `STORE_RECORD` whose signed record we accepted
    /// into the local store (a `STORE_ACK` rides in `responses`).
    pub stored_record: bool,
    /// The frame was a `FIND_VALUE` we answered (with `FOUND_VALUE` if we
    /// held a record, else `FOUND_NODE` with the closest contacts).
    pub find_value_received: bool,
    /// The frame was a `STORE_ACK`; the `request_id` it answered (so the
    /// caller can resolve the matching publish query).
    pub store_ack_request_id: Option<u32>,
    /// For a `FOUND_VALUE`, the `request_id` it answered plus the raw
    /// (still publisher-signed) record blobs it carried.
    pub found_value: Option<(u32, Vec<Vec<u8>>)>,
    /// We learned (added) a new contact from this frame's signed sender.
    pub learned_contact: bool,
    /// Full-bucket liveness checks the caller should perform: each is the
    /// current oldest contact `(addr, node_id, noise_pub)` of a bucket that
    /// just rejected a newcomer into its replacement cache. The caller pings
    /// the contact and, if it stays silent, calls
    /// [`EmberDht::evict_contact`] to promote the cached newcomer
    /// (Kademlia's least-recently-seen eviction rule).
    pub ping_oldest: Vec<(SocketAddr, EmberNodeId, [u8; 32])>,
    /// Decode / signature / identity-binding failure. The caller should
    /// drop the frame; the string is for debug logging only.
    pub error: Option<String>,
}

/// Owns our DHT identity, routing table, and local record store, and
/// turns inbound frames into routing/store updates plus signed replies.
pub struct EmberDht {
    signing_key: SigningKey,
    local_id: EmberNodeId,
    routing: RoutingTable,
    /// Signed key→records store this node serves to `FIND_VALUE`
    /// queries (it is one of the k closest to those keys).
    store: DhtStore,
    /// Monotonic request-id source for outbound requests. Wraps,
    /// skipping 0 so a live waiter can never key on the sentinel.
    next_request_id: u32,
}

impl EmberDht {
    /// Build the engine from our persistent Ed25519 secret key
    /// (`NodeIdentity::ed25519_secret_key`). Our node ID is
    /// `BLAKE3(ed25519_pub)[..16]`, identical to the `ember_hash`, so
    /// every Ember subsystem agrees on who we are.
    pub fn new(ed25519_secret_key: [u8; 32]) -> Self {
        let signing_key = crypto::signing_key_from_bytes(&ed25519_secret_key);
        let local_id = EmberNodeId(crypto::node_id_from_public_key(&signing_key.verifying_key()));
        Self {
            routing: RoutingTable::new(local_id),
            store: DhtStore::new(),
            signing_key,
            local_id,
            next_request_id: 1,
        }
    }

    /// Our 128-bit DHT node ID.
    pub fn local_id(&self) -> EmberNodeId {
        self.local_id
    }

    /// Our Ed25519 public key (peers need this to add us as a contact
    /// and to verify our signed frames).
    pub fn ed25519_public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Number of live contacts across all k-buckets.
    pub fn contact_count(&self) -> usize {
        self.routing.total_contacts()
    }

    /// Snapshot of every contact (for the dev panel / diagnostics).
    pub fn contacts(&self) -> Vec<EmberContact> {
        self.routing.all_contacts()
    }

    /// Borrow the routing table (read-only). The iterative-lookup driver
    /// uses it to seed a search's shortlist with our k closest contacts
    /// to the target.
    pub fn routing(&self) -> &RoutingTable {
        &self.routing
    }

    /// Insert a contact directly (manual harness seeding). Returns
    /// `true` if it landed in a bucket, `false` if rejected (self,
    /// subnet-diversity limit) or only cached behind a full bucket.
    pub fn add_contact(&mut self, contact: EmberContact) -> bool {
        matches!(self.routing.add_contact(contact), AddResult::Added)
    }

    /// Whether we should accept a `STORE_RECORD` for `key`.
    ///
    /// On a sparse routing table we cannot tell whether we are among the k
    /// nodes closest to `key`, so we accept — the per-key / global capacity
    /// caps in [`DhtStore`] bound abuse, and rejecting here would break
    /// publishing on a young network where the publisher's "k closest" set
    /// necessarily includes far-away nodes. Once the table is large enough to
    /// be selective (`>= K_BUCKET_SIZE` known contacts), we only store keys we
    /// are plausibly close to, so a spammer cannot push unrelated records onto
    /// nodes that have no business holding them.
    fn store_proximity_ok(&self, key: &[u8; 16]) -> bool {
        if self.routing.total_contacts() < K_BUCKET_SIZE {
            return true;
        }
        DhtStore::should_store(&self.local_id, key)
    }

    fn next_request_id(&mut self) -> u32 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        if self.next_request_id == 0 {
            self.next_request_id = 1;
        }
        id
    }

    /// Build a signed `PING` frame addressed from us. Returns the
    /// `request_id` (for pending-waiter tracking) and the wire bytes.
    /// The frame includes our Ed25519 public key so a peer who has
    /// never seen us can verify the signature and learn our identity.
    pub fn build_ping(&mut self) -> (u32, Vec<u8>) {
        let request_id = self.next_request_id();
        let msg = messages::build_ping(self.local_id, request_id);
        let bytes = messages::encode_message(&msg, &self.signing_key, true);
        (request_id, bytes)
    }

    /// Build a signed `FIND_NODE` frame querying for `target`. Returns
    /// the `request_id` and the wire bytes. The answer (`FOUND_NODE`)
    /// arrives via [`Self::handle_message`] as `found_node`.
    pub fn build_find_node(&mut self, target: EmberNodeId) -> (u32, Vec<u8>) {
        let request_id = self.next_request_id();
        let msg = messages::build_find_node(self.local_id, request_id, target);
        let bytes = messages::encode_message(&msg, &self.signing_key, true);
        (request_id, bytes)
    }

    /// Build a signed `STORE_RECORD` frame carrying a publisher-signed
    /// `record` under `key`. The answer (`STORE_ACK`) arrives via
    /// [`Self::handle_message`] as `store_ack_request_id`.
    pub fn build_store(
        &mut self,
        key: [u8; 16],
        record: Vec<u8>,
        record_signature: [u8; 64],
    ) -> (u32, Vec<u8>) {
        let request_id = self.next_request_id();
        let msg =
            messages::build_store_record(self.local_id, request_id, key, record, record_signature);
        let bytes = messages::encode_message(&msg, &self.signing_key, true);
        (request_id, bytes)
    }

    /// Build a signed `FIND_VALUE` frame querying for `keys`. The answer
    /// (`FOUND_VALUE`, or `FOUND_NODE` if the peer has no record) arrives
    /// via [`Self::handle_message`].
    pub fn build_find_value(&mut self, keys: Vec<[u8; 16]>) -> (u32, Vec<u8>) {
        let request_id = self.next_request_id();
        let msg = messages::build_find_value(self.local_id, request_id, keys);
        let bytes = messages::encode_message(&msg, &self.signing_key, true);
        (request_id, bytes)
    }

    /// Sign a keyword record with our identity, ready to publish. The
    /// engine owns the signing key, so record construction lives here.
    pub fn build_keyword_record(
        &self,
        keyword: &str,
        file_hash: [u8; 16],
        ember_file_hash: [u8; 32],
        file_size: u64,
        file_name: &str,
    ) -> SignedRecord {
        SignedRecord::keyword(
            keyword,
            file_hash,
            ember_file_hash,
            file_size,
            file_name,
            &self.signing_key,
        )
    }

    /// Sign a source record advertising `contact` as a source for
    /// `file_hash`, ready to publish on the file's source key. The contact
    /// is part of the signed payload, so a downloader can dial it after
    /// verifying the signature.
    pub fn build_source_record(
        &self,
        file_hash: [u8; 16],
        ember_file_hash: [u8; 32],
        file_size: u64,
        file_name: &str,
        contact: SourceContact,
    ) -> SignedRecord {
        SignedRecord::source(
            file_hash,
            ember_file_hash,
            file_size,
            file_name,
            contact,
            &self.signing_key,
        )
    }

    /// Local store stats `(distinct_keys, total_records)` for diagnostics.
    pub fn store_stats(&self) -> (usize, usize) {
        (self.store.key_count(), self.store.total_records())
    }

    /// Drop expired records from the local store. Returns how many went.
    pub fn expire_records(&mut self) -> usize {
        self.store.expire()
    }

    // ── Persistence (slice 7) ──

    /// Bulk-load persisted contacts (from `nodes_ember.dat`) into the
    /// routing table at startup.
    pub fn load_contacts(&mut self, contacts: Vec<EmberContact>) {
        self.routing.load_contacts(contacts);
    }

    // ── Maintenance (slice 6) ──

    /// Bucket indices to refresh this cycle (stalest first, capped at
    /// `max`). See [`RoutingTable::buckets_for_refresh`].
    pub fn buckets_for_refresh(&self, threshold_secs: i64, max: usize, force: bool) -> Vec<usize> {
        self.routing.buckets_for_refresh(threshold_secs, max, force)
    }

    /// Generate a random target ID that falls in bucket `bucket_idx`
    /// relative to our own ID — i.e. the XOR distance from us has its
    /// highest set bit at `bucket_idx`. A `FIND_NODE` for this target
    /// refreshes that bucket (standard Kademlia bucket refresh).
    pub fn random_target_in_bucket(&self, bucket_idx: usize) -> EmberNodeId {
        let mut d = [0u8; 16];
        for byte in d.iter_mut() {
            *byte = rand::random();
        }
        // Bit `i` (0 = LSB of the last byte … 127 = MSB of the first byte)
        // maps to byte `15 - i/8`, bit `i % 8`. For the leading set bit to
        // land exactly at `bucket_idx`: clear every higher bit, set
        // `bucket_idx`, leave lower bits random.
        for i in 0..ID_BITS {
            let byte = 15 - i / 8;
            let bit = i % 8;
            if i > bucket_idx {
                d[byte] &= !(1 << bit);
            } else if i == bucket_idx {
                d[byte] |= 1 << bit;
            }
        }
        let mut target = [0u8; 16];
        for j in 0..16 {
            target[j] = self.local_id.0[j] ^ d[j];
        }
        EmberNodeId(target)
    }

    /// Contacts to liveness-ping this cycle: those not heard from in more
    /// than `threshold_secs` (or all, oldest first, when `force`), capped
    /// at `max`.
    pub fn contacts_due_for_ping(
        &self,
        now: i64,
        threshold_secs: i64,
        max: usize,
        force: bool,
    ) -> Vec<EmberContact> {
        let mut due: Vec<EmberContact> = self
            .routing
            .all_contacts()
            .into_iter()
            .filter(|c| force || (now - c.last_seen) > threshold_secs)
            .collect();
        due.sort_by_key(|c| c.last_seen); // stalest first
        due.truncate(max);
        due
    }

    /// Record one failed liveness query against a contact. Returns `true`
    /// if it has now exceeded `MAX_FAILED_QUERIES` and should be evicted.
    pub fn mark_failed_contact(&mut self, node_id: &EmberNodeId) -> bool {
        self.routing.mark_failed(node_id)
    }

    /// Evict a dead contact and promote a replacement from the cache.
    pub fn evict_contact(&mut self, node_id: &EmberNodeId) -> bool {
        self.routing.evict_and_replace(node_id)
    }

    /// Collect locally-stored records due for republish (see
    /// [`DhtStore::take_republish_batch`]).
    pub fn take_republish_batch(
        &mut self,
        interval: std::time::Duration,
        max: usize,
        force: bool,
    ) -> Vec<(Vec<u8>, [u8; 64])> {
        self.store.take_republish_batch(interval, max, force)
    }

    /// Handle one decrypted inbound DHT frame from `from` over a Noise
    /// session whose peer static key is `remote_noise_pub`. `now` is a
    /// unix timestamp used for contact freshness.
    ///
    /// Every validly-signed frame teaches us a contact (Kademlia learns
    /// from all traffic). A `PING` additionally yields a signed `PONG`
    /// in `responses`.
    pub fn handle_message(
        &mut self,
        payload: &[u8],
        from: SocketAddr,
        remote_noise_pub: [u8; 32],
        now: i64,
    ) -> DhtInbound {
        let mut out = DhtInbound::default();

        // `decode_message(.., true)` verifies the Ed25519 signature and
        // the `sender_id == BLAKE3(pubkey)[..16]` binding, so a frame
        // that decodes here is cryptographically attributable to its
        // sender_id and cannot poison the table under a forged ID.
        let msg = match messages::decode_message(payload, true) {
            Ok(m) => m,
            Err(e) => {
                out.error = Some(e.to_string());
                return out;
            }
        };
        out.sender_id = Some(msg.sender_id);

        // Learn the sender as a contact. `sender_pub_key` is always
        // present because we decoded with `has_pub_key = true`; the
        // binding check above guarantees it matches `sender_id`.
        if let Some(ed25519_pub) = msg.sender_pub_key {
            let contact = EmberContact {
                node_id: msg.sender_id,
                addr: from,
                noise_pub: remote_noise_pub,
                ed25519_pub,
                last_seen: now,
                failed_queries: 0,
            };
            match self.routing.add_contact(contact) {
                AddResult::Added => out.learned_contact = true,
                AddResult::PingOldest {
                    addr,
                    node_id,
                    noise_pub,
                } => out.ping_oldest.push((addr, node_id, noise_pub)),
                AddResult::Rejected => {}
            }
        }

        match msg.payload {
            DhtPayload::Ping => {
                out.ping_received = true;
                let pong = messages::build_pong(self.local_id, msg.request_id);
                out.responses
                    .push(messages::encode_message(&pong, &self.signing_key, true));
            }
            DhtPayload::Pong => {
                out.pong_received = true;
                out.pong_request_id = Some(msg.request_id);
                // The PONG proves liveness; refresh the contact's
                // bucket position so it isn't evicted as stale.
                self.routing.mark_alive(&msg.sender_id);
            }
            DhtPayload::FindNode { target } => {
                out.find_node_received = true;
                let closest = self.routing.find_closest(&target, MAX_CONTACTS_PER_RESPONSE);
                let found =
                    messages::build_found_node(self.local_id, msg.request_id, closest);
                out.responses
                    .push(messages::encode_message(&found, &self.signing_key, true));
            }
            DhtPayload::FoundNode { contacts } => {
                // Merge every returned contact into the table (standard
                // Kademlia learns from lookup responses). Each contact
                // is unverified — it rode inside a signed frame from
                // `from`, but we have not heard from it directly — so it
                // enters with the `last_seen` the wire carried (0) and
                // will be pinged before later slices trust it.
                for contact in &contacts {
                    if let AddResult::PingOldest {
                        addr,
                        node_id,
                        noise_pub,
                    } = self.routing.add_contact(contact.clone())
                    {
                        out.ping_oldest.push((addr, node_id, noise_pub));
                    }
                }
                out.found_node = Some((msg.request_id, contacts));
            }
            DhtPayload::StoreRecord {
                key,
                record,
                record_signature,
            } => {
                // Parse + verify the publisher-signed record, and bind the
                // DHT key to the record's own content key so a publisher
                // can't scatter a record under unrelated keys. `from_wire`
                // verifies the Ed25519 signature; `DhtStore::store` checks
                // it again (defence in depth) and enforces capacity.
                if let Some(parsed) = SignedRecord::from_wire(&record, record_signature) {
                    // Anti-reflection for source records: the publisher's
                    // self-reported IP must match the observed Noise sender IP,
                    // so a peer cannot publish a record that points downloaders
                    // at a third-party victim. Honest publishers store their own
                    // source record from their own address, and source records
                    // are deliberately not relayed by other nodes (see
                    // `DhtStore::take_republish_batch`), so this binding always
                    // holds for legitimate stores. Non-source records carry no
                    // address and are unaffected.
                    let source_ip_ok = match parsed.source_contact {
                        Some(sc) => from.ip() == std::net::IpAddr::V4(sc.ip),
                        None => parsed.record_type != RECORD_TYPE_SOURCE,
                    };
                    if key == parsed.keyword_hash
                        && source_ip_ok
                        && self.store_proximity_ok(&key)
                        && self.store.store(
                            key,
                            record,
                            record_signature,
                            parsed.publisher_key,
                            parsed.timestamp,
                        )
                    {
                        out.stored_record = true;
                        let ack = messages::build_store_ack(self.local_id, msg.request_id, key);
                        out.responses
                            .push(messages::encode_message(&ack, &self.signing_key, true));
                    }
                }
                // A record that fails to parse/verify, whose key does not
                // match its content, or (for a source record) whose claimed
                // IP doesn't match the sender, is dropped with no ACK so the
                // publisher's success count reflects only real storage.
            }
            DhtPayload::FindValue { keys } => {
                out.find_value_received = true;
                // Answer with the records for the first requested key we
                // hold; otherwise fall back to the closest contacts so the
                // searcher can keep walking toward a node that has it.
                let mut answered = false;
                for key in &keys {
                    // Serve only live records — an expired record that the
                    // periodic sweep hasn't reaped yet must never satisfy a
                    // lookup.
                    let records = self.store.get_live(key);
                    if !records.is_empty() {
                        // Each FOUND_VALUE blob is `record_data ||
                        // 64-byte publisher signature` so the searcher
                        // can re-verify it end-to-end (the wire frame's
                        // own signature only proves *we* relayed it).
                        let blobs: Vec<Vec<u8>> = records
                            .iter()
                            .map(|r| {
                                let mut b = Vec::with_capacity(r.data.len() + 64);
                                b.extend_from_slice(&r.data);
                                b.extend_from_slice(&r.signature);
                                b
                            })
                            .collect();
                        let fv = messages::build_found_value(
                            self.local_id,
                            msg.request_id,
                            *key,
                            blobs,
                        );
                        out.responses
                            .push(messages::encode_message(&fv, &self.signing_key, true));
                        answered = true;
                        break;
                    }
                }
                if !answered {
                    let target = keys
                        .first()
                        .map(|k| EmberNodeId(*k))
                        .unwrap_or(self.local_id);
                    let closest = self.routing.find_closest(&target, MAX_CONTACTS_PER_RESPONSE);
                    let found =
                        messages::build_found_node(self.local_id, msg.request_id, closest);
                    out.responses
                        .push(messages::encode_message(&found, &self.signing_key, true));
                }
            }
            DhtPayload::StoreAck { key: _ } => {
                out.store_ack_request_id = Some(msg.request_id);
            }
            DhtPayload::FoundValue { key: _, records } => {
                out.found_value = Some((msg.request_id, records));
            }
            other => {
                // ANNOUNCE_PEER / PEER_LIST / Unknown arrive here once
                // peers speak them, but their handlers land in later
                // slices. We've already learned the sender above.
                trace!(
                    "Ember DHT: ignoring unhandled message type from {from}: {:?}",
                    std::mem::discriminant(&other)
                );
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dht(seed: u8) -> EmberDht {
        EmberDht::new([seed; 32])
    }

    fn addr(last: u8, port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, last], port))
    }

    #[test]
    fn node_id_is_ember_hash_of_pubkey() {
        let d = dht(7);
        let expected = crypto::node_id_from_public_key(
            &crypto::verifying_key_from_bytes(&d.ed25519_public_key()).unwrap(),
        );
        assert_eq!(d.local_id().0, expected);
    }

    #[test]
    fn ping_pong_round_trip_learns_both_contacts() {
        let mut a = dht(1);
        let mut b = dht(2);
        let a_noise = [0xAA; 32];
        let b_noise = [0xBB; 32];
        let a_addr = addr(1, 4672);
        let b_addr = addr(2, 4672);

        // A pings B.
        let (rid, ping_bytes) = a.build_ping();
        let on_b = b.handle_message(&ping_bytes, a_addr, a_noise, 1000);
        assert!(on_b.ping_received, "B should see a PING");
        assert!(on_b.error.is_none());
        assert_eq!(on_b.responses.len(), 1, "B should answer with one PONG");
        assert!(on_b.learned_contact, "B should learn A");
        assert_eq!(b.contact_count(), 1);

        // B's PONG comes back to A.
        let on_a = a.handle_message(&on_b.responses[0], b_addr, b_noise, 1001);
        assert!(on_a.pong_received, "A should see a PONG");
        assert_eq!(on_a.pong_request_id, Some(rid), "PONG must echo A's request id");
        assert!(on_a.learned_contact, "A should learn B");
        assert_eq!(a.contact_count(), 1);

        // The learned contacts carry the Noise key from the session,
        // which the DHT could not otherwise know.
        let a_knows = a.contacts();
        assert_eq!(a_knows[0].node_id, b.local_id());
        assert_eq!(a_knows[0].noise_pub, b_noise);
        assert_eq!(a_knows[0].addr, b_addr);
    }

    #[test]
    fn find_node_returns_closest_and_asker_learns_them() {
        let mut a = dht(10);
        let mut b = dht(11);
        let a_noise = [0xAA; 32];
        let b_noise = [0xBB; 32];
        let a_addr = addr(10, 4672);
        let b_addr = addr(11, 4672);

        // Seed B with a third contact C so it has something to return.
        let c = dht(12);
        let c_contact = EmberContact {
            node_id: c.local_id(),
            addr: addr(12, 4672),
            noise_pub: [0xCC; 32],
            ed25519_pub: c.ed25519_public_key(),
            last_seen: 500,
            failed_queries: 0,
        };
        assert!(b.add_contact(c_contact));

        // A asks B to find a target.
        let target = EmberNodeId([0x42; 16]);
        let (rid, find_bytes) = a.build_find_node(target);
        let on_b = b.handle_message(&find_bytes, a_addr, a_noise, 1000);
        assert!(on_b.find_node_received, "B should see a FIND_NODE");
        assert!(on_b.error.is_none());
        assert_eq!(on_b.responses.len(), 1, "B answers with one FOUND_NODE");
        assert!(on_b.learned_contact, "B learns A (the asker)");

        // B's FOUND_NODE returns to A.
        let on_a = a.handle_message(&on_b.responses[0], b_addr, b_noise, 1001);
        let (got_rid, contacts) = on_a.found_node.expect("A should see a FOUND_NODE");
        assert_eq!(got_rid, rid, "FOUND_NODE must echo the request id");
        assert!(
            contacts.iter().any(|x| x.node_id == c.local_id()),
            "B should have returned contact C"
        );
        // A merged the returned contacts AND learned B (the responder).
        assert!(
            a.contacts().iter().any(|x| x.node_id == c.local_id()),
            "A should have learned C from the FOUND_NODE"
        );
        assert!(
            a.contacts().iter().any(|x| x.node_id == b.local_id()),
            "A should have learned B (the responder)"
        );
    }

    #[test]
    fn store_then_find_value_round_trip() {
        let mut a = dht(20); // publisher / searcher
        let mut b = dht(21); // storer
        let a_noise = [0xAA; 32];
        let b_noise = [0xBB; 32];
        let a_addr = addr(20, 4672);
        let b_addr = addr(21, 4672);

        // A signs a keyword record and stores it on B.
        let record = a.build_keyword_record("ubuntu", [9u8; 16], [0u8; 32], 4096, "ubuntu.iso");
        let key = record.keyword_hash;
        let (store_rid, store_bytes) = a.build_store(key, record.data.clone(), record.signature);
        let on_b = b.handle_message(&store_bytes, a_addr, a_noise, 1000);
        assert!(on_b.stored_record, "B should accept the signed record");
        assert_eq!(on_b.responses.len(), 1, "B answers with one STORE_ACK");
        assert_eq!(b.store_stats(), (1, 1));

        // The STORE_ACK returns to A.
        let on_a = a.handle_message(&on_b.responses[0], b_addr, b_noise, 1001);
        assert_eq!(on_a.store_ack_request_id, Some(store_rid));

        // A asks B for the value.
        let (find_rid, find_bytes) = a.build_find_value(vec![key]);
        let on_b2 = b.handle_message(&find_bytes, a_addr, a_noise, 1002);
        assert!(on_b2.find_value_received);
        assert_eq!(on_b2.responses.len(), 1, "B answers with one FOUND_VALUE");

        // The FOUND_VALUE returns to A; the blob re-verifies and matches.
        let on_a2 = a.handle_message(&on_b2.responses[0], b_addr, b_noise, 1003);
        let (got_rid, blobs) = on_a2.found_value.expect("A should see a FOUND_VALUE");
        assert_eq!(got_rid, find_rid);
        assert_eq!(blobs.len(), 1);
        let parsed = SignedRecord::from_value_blob(&blobs[0]).expect("record verifies");
        assert_eq!(parsed.file_name, "ubuntu.iso");
        assert_eq!(parsed.file_size, 4096);
        assert_eq!(parsed.keyword_hash, key);
    }

    fn source_contact_at(last: u8) -> SourceContact {
        SourceContact {
            ip: std::net::Ipv4Addr::new(10, 0, 0, last),
            tcp_port: 4662,
            udp_port: 4672,
            flags: 0,
            noise_pub: [0x44; 32],
        }
    }

    #[test]
    fn source_store_then_find_value_round_trip() {
        let mut a = dht(60); // publisher (the source itself)
        let mut b = dht(61); // storer
        let a_noise = [0xAA; 32];
        let b_noise = [0xBB; 32];
        let a_addr = addr(20, 4672); // 10.0.0.20 — matches the claimed contact IP
        let b_addr = addr(21, 4672);

        // A advertises itself as a source. The claimed contact IP matches the
        // address B observes A storing from, so the anti-reflection check
        // passes (honest self-publish).
        let contact = source_contact_at(20);
        let record = a.build_source_record([7u8; 16], [0u8; 32], 1234, "movie.mkv", contact);
        let key = record.keyword_hash;
        let (_rid, store_bytes) = a.build_store(key, record.data.clone(), record.signature);
        let on_b = b.handle_message(&store_bytes, a_addr, a_noise, 1000);
        assert!(on_b.stored_record, "B should accept a source record from A's own IP");
        assert_eq!(b.store_stats(), (1, 1));

        // B serves it back on FIND_VALUE and the embedded contact survives the
        // end-to-end round trip and re-verification.
        let (_frid, find_bytes) = a.build_find_value(vec![key]);
        let on_b2 = b.handle_message(&find_bytes, a_addr, a_noise, 1002);
        let on_a2 = a.handle_message(&on_b2.responses[0], b_addr, b_noise, 1003);
        let (_grid, blobs) = on_a2.found_value.expect("A should see a FOUND_VALUE");
        assert_eq!(blobs.len(), 1);
        let parsed = SignedRecord::from_value_blob(&blobs[0]).expect("record verifies");
        assert_eq!(parsed.record_type, RECORD_TYPE_SOURCE);
        assert_eq!(parsed.source_contact, Some(contact));
    }

    #[test]
    fn source_store_rejected_on_ip_mismatch() {
        let mut a = dht(62);
        let mut b = dht(63);
        let a_noise = [0xAA; 32];
        let a_addr = addr(30, 4672); // 10.0.0.30

        // The record claims a *different* IP (10.0.0.99) than the address B
        // observes the STORE arriving from — a third-party reflection attempt.
        let contact = source_contact_at(99);
        let record = a.build_source_record([8u8; 16], [0u8; 32], 10, "x", contact);
        let key = record.keyword_hash;
        let (_rid, store_bytes) = a.build_store(key, record.data.clone(), record.signature);
        let on_b = b.handle_message(&store_bytes, a_addr, a_noise, 1000);
        assert!(!on_b.stored_record, "claimed IP != sender IP must be rejected");
        assert!(on_b.responses.is_empty(), "no STORE_ACK on reflection rejection");
        assert_eq!(b.store_stats(), (0, 0));
    }

    #[test]
    fn find_value_without_record_returns_closest_nodes() {
        let mut a = dht(30);
        let mut b = dht(31);
        let a_noise = [0xAA; 32];
        let b_noise = [0xBB; 32];
        let a_addr = addr(30, 4672);
        let b_addr = addr(31, 4672);

        // Seed B with a contact C so it has a fallback to return.
        let c = dht(32);
        let c_contact = EmberContact {
            node_id: c.local_id(),
            addr: addr(32, 4672),
            noise_pub: [0xCC; 32],
            ed25519_pub: c.ed25519_public_key(),
            last_seen: 500,
            failed_queries: 0,
        };
        assert!(b.add_contact(c_contact));

        // A asks for a key B does not hold.
        let (find_rid, find_bytes) = a.build_find_value(vec![[0x55u8; 16]]);
        let on_b = b.handle_message(&find_bytes, a_addr, a_noise, 1000);
        assert!(on_b.find_value_received);
        assert_eq!(on_b.responses.len(), 1, "B falls back to FOUND_NODE");

        // A receives FOUND_NODE (not FOUND_VALUE) with C in it.
        let on_a = a.handle_message(&on_b.responses[0], b_addr, b_noise, 1001);
        assert!(on_a.found_value.is_none(), "no value should be returned");
        let (got_rid, contacts) = on_a.found_node.expect("A should get FOUND_NODE fallback");
        assert_eq!(got_rid, find_rid);
        assert!(contacts.iter().any(|x| x.node_id == c.local_id()));
    }

    #[test]
    fn store_rejects_key_content_mismatch() {
        let mut a = dht(40);
        let mut b = dht(41);
        let a_noise = [0xAA; 32];
        let a_addr = addr(40, 4672);

        let record = a.build_keyword_record("debian", [1u8; 16], [0u8; 32], 10, "d.iso");
        // Claim a key that does not match the record's content key.
        let bogus_key = [0xEE; 16];
        let (_rid, store_bytes) = a.build_store(bogus_key, record.data.clone(), record.signature);
        let on_b = b.handle_message(&store_bytes, a_addr, a_noise, 1000);
        assert!(!on_b.stored_record, "key/content mismatch must be rejected");
        assert!(on_b.responses.is_empty(), "no STORE_ACK on rejection");
        assert_eq!(b.store_stats(), (0, 0));
    }

    #[test]
    fn random_target_lands_in_requested_bucket() {
        let d = dht(55);
        let local = d.local_id();
        // Every bucket index must produce a target whose XOR distance from
        // us has its leading bit exactly at that index.
        for bucket in [0usize, 1, 63, 119, 120, 126, 127] {
            for _ in 0..16 {
                let target = d.random_target_in_bucket(bucket);
                assert_ne!(target, local, "target must differ from us");
                assert_eq!(
                    local.bucket_index(&target),
                    Some(bucket),
                    "target for bucket {bucket} landed in the wrong bucket"
                );
            }
        }
    }

    #[test]
    fn tampered_frame_is_rejected_and_teaches_nothing() {
        let mut a = dht(3);
        let mut b = dht(4);
        let (_rid, mut ping_bytes) = a.build_ping();

        // Flip a byte inside the signed region (the request id).
        ping_bytes[3] ^= 0xFF;

        let on_b = b.handle_message(&ping_bytes, addr(3, 4672), [0xAA; 32], 1000);
        assert!(on_b.error.is_some(), "signature check must fail");
        assert!(!on_b.ping_received);
        assert!(on_b.responses.is_empty());
        assert_eq!(b.contact_count(), 0, "a forged frame must not seed the table");
    }

    #[test]
    fn manual_add_contact_seeds_table() {
        let mut a = dht(5);
        let peer = dht(6);
        let contact = EmberContact {
            node_id: peer.local_id(),
            addr: addr(6, 4672),
            noise_pub: [0xCC; 32],
            ed25519_pub: peer.ed25519_public_key(),
            last_seen: 1000,
            failed_queries: 0,
        };
        assert!(a.add_contact(contact));
        assert_eq!(a.contact_count(), 1);
    }
}
