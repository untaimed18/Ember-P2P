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

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use tracing::trace;

use super::messages::{self, DhtPayload};
use super::publish::{SignedRecord, SourceContact, RECORD_TYPE_SOURCE};
use super::routing::{AddResult, RoutingTable};
use super::store::{DhtStore, DhtStoreEntry};
use super::{EmberContact, EmberNodeId, ID_BITS, K_BUCKET_SIZE, MAX_CONTACTS_PER_RESPONSE};
use crate::network::ember::crypto;
use crate::network::ember::SOURCE_FLAG_FIREWALLED;

/// Collapse identical STORE frames for this long (slice 14). Hourly
/// keyword republish still gets through.
const STORE_SIG_REPLAY_TTL: Duration = Duration::from_secs(60);
const MAX_STORE_SIG_CACHE: usize = 50_000;

/// Share of the liveness-ping budget held for unverified leads when there are
/// enough verified contacts due to spend the whole thing. One in four: enough
/// that gossip keeps being promoted once the table is healthy, small enough
/// that the contacts we actually route through stay refreshed.
const LEAD_PING_RESERVE_DIVISOR: usize = 4;

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
    /// Observed address echoed in a `PONG` payload (slice 19), if present.
    pub pong_observed: Option<SocketAddr>,
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
    /// True when that `FIND_VALUE` was answered with `FOUND_VALUE` (hit).
    pub find_value_hit: bool,
    /// Live matching records that did not fit the `FOUND_VALUE` datagram.
    ///
    /// Non-zero means this node holds more under the key than one answer can
    /// ever carry, and the same front-of-list records are the only ones it
    /// serves. Without this the shortfall is indistinguishable from a small
    /// network, which is the evidence needed before paying for pagination.
    pub find_value_withheld: u16,
    /// The frame was a `STORE_ACK`; the `request_id` it answered (so the
    /// caller can resolve the matching publish query).
    pub store_ack_request_id: Option<u32>,
    /// The frame was a `STORE_BATCH_ACK`: `(request_id, accepted bitmap)`.
    pub store_batch_ack: Option<(u32, u64)>,
    /// How many records an inbound `STORE_BATCH` contributed to our store.
    pub batch_records_stored: u16,
    /// For a `FOUND_VALUE`, the `request_id` it answered plus the raw
    /// (still publisher-signed) record blobs it carried.
    pub found_value: Option<(u32, Vec<Vec<u8>>)>,
    /// The frame was an `ANNOUNCE_PEER` we answered with a `PEER_LIST`.
    pub announce_peer_received: bool,
    /// For a `PEER_LIST`, the `request_id` it answered plus the contacts
    /// it carried (also merged into the routing table).
    pub peer_list: Option<(u32, Vec<EmberContact>)>,
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
    /// Slice 14: identical STORE signature rejected as a replay.
    pub store_replay_rejected: bool,
    /// A verified `PROXY_STORE` the caller should fan out via the normal
    /// publish driver (buddy-assisted firewalled source publish).
    /// Carries the wire `request_id` so the caller can ACK only after
    /// `start_publish` succeeds.
    pub proxy_store_forward: Option<(u32, SignedRecord)>,
}

/// What happened to one record offered to the local store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreOutcome {
    Stored,
    /// The same publisher signature arrived again inside the replay window.
    Replay,
    /// Failed verification, key binding, anti-reflection, proximity, or a
    /// store capacity limit.
    Rejected,
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
    /// Recently-seen STORE signatures (`blake3(publisher||sig)` → time)
    /// for slice-14 replay collapse.
    store_sig_seen: HashMap<[u8; 32], Instant>,
    /// When `store_sig_seen` was last swept, so the scan runs on a schedule
    /// rather than once per record of every oversized batch.
    store_sig_swept_at: Option<Instant>,
}

impl EmberDht {
    /// Build the engine from our persistent Ed25519 secret key
    /// (`NodeIdentity::ed25519_secret_key`). Our node ID is
    /// `BLAKE3(ed25519_pub)[..16]`, identical to the `ember_hash`, so
    /// every Ember subsystem agrees on who we are.
    pub fn new(ed25519_secret_key: [u8; 32], block_private_ips: bool) -> Self {
        let signing_key = crypto::signing_key_from_bytes(&ed25519_secret_key);
        let local_id = EmberNodeId(crypto::node_id_from_public_key(
            &signing_key.verifying_key(),
        ));
        let mut store = DhtStore::new();
        // The store ranks records by how responsible we are for their key
        // when it has to free space.
        store.set_local_id(local_id);
        Self {
            routing: RoutingTable::new(local_id, block_private_ips),
            store,
            signing_key,
            local_id,
            next_request_id: 1,
            store_sig_seen: HashMap::new(),
            store_sig_swept_at: None,
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

    /// Purge contacts that have gone quiet, sparing any an in-flight search
    /// still needs. See [`RoutingTable::remove_stale`].
    pub fn remove_stale_contacts(
        &mut self,
        now: i64,
        max_age_secs: i64,
        in_use: &std::collections::HashSet<EmberNodeId>,
    ) -> usize {
        self.routing.remove_stale(now, max_age_secs, in_use)
    }

    /// Look up a contact by node ID.
    pub fn contact_for(&self, node_id: &EmberNodeId) -> Option<&EmberContact> {
        self.routing.get_contact(node_id)
    }

    /// Contacts worth persisting for the next session: proven, healthy, and
    /// closest to home first. See
    /// [`RoutingTable::export_bootstrap_contacts`].
    pub fn bootstrap_contacts(&self, max: usize) -> Vec<EmberContact> {
        self.routing.export_bootstrap_contacts(max)
    }

    /// Share the user's range IP filter with the routing table so blocked
    /// addresses are refused on admission.
    pub fn set_ip_filter(&mut self, filter: crate::network::kad::ip_filter::SharedIpFilter) {
        self.routing.set_ip_filter(filter);
    }

    /// Hot-update the LAN/CGNAT admission policy, evicting contacts the new
    /// policy rejects. Returns how many were dropped.
    pub fn set_block_private_ips(&mut self, block_private: bool) -> usize {
        self.routing.set_block_private_ips(block_private)
    }

    /// Re-apply the current IP policy to the whole table, for when the user
    /// reloads `ipfilter.dat`.
    pub fn evict_filtered_contacts(&mut self) -> usize {
        self.routing.evict_filtered_contacts()
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
    /// Apply the inbound-STORE acceptance rules to one record.
    ///
    /// Shared by `STORE_RECORD` and every record inside a `STORE_BATCH`, so
    /// the two framings cannot drift into accepting different things.
    fn accept_record(
        &mut self,
        key: [u8; 16],
        record: Vec<u8>,
        record_signature: [u8; 64],
        from: SocketAddr,
    ) -> StoreOutcome {
        // Parse + verify the publisher-signed record, and bind the DHT key to
        // the record's own content key so a publisher can't scatter a record
        // under unrelated keys. `from_wire` verifies the Ed25519 signature;
        // `DhtStore::store` checks it again (defence in depth) and enforces
        // capacity.
        let Some(parsed) = SignedRecord::from_wire(&record, record_signature) else {
            return StoreOutcome::Rejected;
        };

        // Anti-reflection for source records: HighID / direct sources must
        // claim the observed Noise sender IP so a peer cannot point
        // downloaders at a third-party victim. Firewalled sources
        // (`SOURCE_FLAG_FIREWALLED`) are exempt: they may be STORED by a
        // HighID buddy (proxy path) or from a NAT mapping that differs from
        // the STUN hint. Authorship is still bound by the publisher Ed25519
        // signature; the record is not republished by storers (see
        // `DhtStore::take_republish_batch`).
        let source_ip_ok = match parsed.source_contact {
            Some(sc) if sc.flags & SOURCE_FLAG_FIREWALLED != 0 => true,
            Some(sc) => from.ip() == std::net::IpAddr::V4(sc.ip),
            None => parsed.record_type != RECORD_TYPE_SOURCE,
        };

        // Slice 14: collapse identical STORE frames (same publisher
        // signature) for a short window so a retransmit storm can't re-verify
        // the same blob forever. Hourly republish still lands after the TTL.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&parsed.publisher_key);
        hasher.update(&record_signature);
        let sig_key = *hasher.finalize().as_bytes();
        let now_inst = Instant::now();
        // Sweep at most once per TTL. `accept_record` runs once per record, so
        // an unconditional size check meant a single 64-record `STORE_BATCH`
        // could walk a 25,000-entry map 64 times — and nothing expires inside
        // one batch, so 63 of those scans could not free anything.
        let sweep_due = self
            .store_sig_swept_at
            .is_none_or(|at| now_inst.duration_since(at) >= STORE_SIG_REPLAY_TTL);
        if sweep_due && self.store_sig_seen.len() > MAX_STORE_SIG_CACHE / 2 {
            self.store_sig_seen
                .retain(|_, t| now_inst.duration_since(*t) < STORE_SIG_REPLAY_TTL);
            self.store_sig_swept_at = Some(now_inst);
        }
        let is_replay = self
            .store_sig_seen
            .get(&sig_key)
            .map(|t| now_inst.duration_since(*t) < STORE_SIG_REPLAY_TTL)
            .unwrap_or(false);
        if is_replay {
            return StoreOutcome::Replay;
        }

        // A firewalled source's declared address is exempt from the bind
        // above, so nothing vouches for it. Attribute the record to the peer
        // that actually sent it, or one host can invent an address per record
        // and take a whole key's source slots.
        let attributed_ip = match parsed.source_contact {
            Some(sc) if sc.flags & SOURCE_FLAG_FIREWALLED != 0 => match from.ip() {
                std::net::IpAddr::V4(v4) => Some(v4),
                std::net::IpAddr::V6(_) => None,
            },
            _ => None,
        };

        if key == parsed.keyword_hash
            && source_ip_ok
            && self.store_proximity_ok(&key)
            && self.store.store_attributed(
                key,
                record,
                record_signature,
                parsed.publisher_key,
                parsed.timestamp,
                attributed_ip,
            )
        {
            // At capacity, make room rather than stopping: silently declining to
            // record a signature turns off replay collapse for exactly the
            // publishers arriving during a flood, which is when it earns its
            // keep. The oldest entry is the one closest to ageing out anyway.
            if self.store_sig_seen.len() >= MAX_STORE_SIG_CACHE {
                if let Some(oldest) = self
                    .store_sig_seen
                    .iter()
                    .min_by_key(|(_, seen)| **seen)
                    .map(|(k, _)| *k)
                {
                    self.store_sig_seen.remove(&oldest);
                }
            }
            self.store_sig_seen.insert(sig_key, now_inst);
            StoreOutcome::Stored
        } else {
            StoreOutcome::Rejected
        }
    }

    /// Keep the store's abuse limits in step with the routing table, which is
    /// where network size is observed.
    fn sync_store_scale(&mut self) {
        let scale = self.routing.scale();
        self.store.set_scale(scale);
    }

    /// Whether we are one of the nodes responsible for holding `key`.
    ///
    /// This is Kademlia's actual question — am I among the k closest nodes to
    /// this key? — answered against the contacts we know. It replaces a fixed
    /// "close half of the ID space" rule, which rejected half of all keys
    /// outright regardless of whether any closer node existed, and which
    /// switched on the moment the table reached k contacts: exactly when a
    /// small network's every node is still trivially among the k closest to
    /// everything, so replication silently halved just as the network became
    /// interesting.
    ///
    /// Knowing fewer than k contacts means we are among the k closest by
    /// definition, so everything is stored.
    fn store_proximity_ok(&self, key: &[u8; 16]) -> bool {
        let key_id = EmberNodeId(*key);
        let closest = self.routing.find_closest(&key_id, K_BUCKET_SIZE);
        if closest.len() < K_BUCKET_SIZE {
            return true;
        }
        let ours = self.local_id.distance(&key_id);
        let kth = closest
            .last()
            .map(|c| c.node_id.distance(&key_id))
            .unwrap_or(EmberNodeId([0xFF; 16]));
        ours.0 <= kth.0
    }

    /// Contacts closest to `target`, minus the peer that asked.
    ///
    /// The asker is added to our table at the top of `handle_message`, and
    /// its distance to itself is zero, so an unfiltered reply always led with
    /// the one contact it definitely already has — spending a slot of a
    /// response that is capped by both count and datagram size.
    fn closest_excluding(&self, target: &EmberNodeId, asker: EmberNodeId) -> Vec<EmberContact> {
        let mut closest = self
            .routing
            .find_closest(target, MAX_CONTACTS_PER_RESPONSE + 1);
        closest.retain(|c| c.node_id != asker);
        closest.truncate(MAX_CONTACTS_PER_RESPONSE);
        closest
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

    /// Build a signed `ANNOUNCE_PEER` carrying a contact-list gossip dump.
    /// The peer answers with `PEER_LIST` (see [`Self::handle_message`]).
    pub fn build_announce_peer(&mut self, contacts: Vec<EmberContact>) -> (u32, Vec<u8>) {
        let request_id = self.next_request_id();
        let msg = messages::build_announce_peer(self.local_id, request_id, contacts);
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

    /// Ask a HighID buddy to fan out our publisher-signed firewalled source
    /// record (`PROXY_STORE`). Same payload shape as `STORE_RECORD`.
    pub fn build_proxy_store(
        &mut self,
        key: [u8; 16],
        record: Vec<u8>,
        record_signature: [u8; 64],
    ) -> (u32, Vec<u8>) {
        let request_id = self.next_request_id();
        let msg =
            messages::build_proxy_store(self.local_id, request_id, key, record, record_signature);
        let bytes = messages::encode_message(&msg, &self.signing_key, true);
        (request_id, bytes)
    }

    /// Sign a `PROXY_STORE_ACK` for `request_id` / `key` (caller sends after
    /// successfully starting the fan-out publish).
    pub fn build_proxy_store_ack_frame(&self, request_id: u32, key: [u8; 16]) -> Vec<u8> {
        let msg = messages::build_proxy_store_ack(self.local_id, request_id, key);
        messages::encode_message(&msg, &self.signing_key, true)
    }

    /// Build a signed `FIND_VALUE` frame querying for `keys`. The answer
    /// (`FOUND_VALUE`, or `FOUND_NODE` if the peer has no record) arrives
    /// via [`Self::handle_message`].
    ///
    /// Keys past [`messages::MAX_FIND_VALUE_KEYS`] are dropped. A peer rejects
    /// an over-long request at decode and answers nothing at all, so sending
    /// one would cost the whole query timeout and return no contacts either;
    /// callers pass keys most-selective-first, and the keywords dropped here
    /// are still applied by the caller's own filename filter. Truncating is
    /// therefore strictly better than letting a long query go unanswered.
    pub fn build_find_value(&mut self, mut keys: Vec<[u8; 16]>) -> (u32, Vec<u8>) {
        keys.truncate(messages::MAX_FIND_VALUE_KEYS);
        let request_id = self.next_request_id();
        let msg = messages::build_find_value(self.local_id, request_id, keys);
        let bytes = messages::encode_message(&msg, &self.signing_key, true);
        (request_id, bytes)
    }

    /// Build a signed `STORE_BATCH` carrying as many of `records` as fit one
    /// unfragmented datagram.
    ///
    /// Returns the frame, its request id, and how many records it took, so
    /// the caller can send the remainder in a following batch. Returns `None`
    /// when `records` is empty or the first record alone is too large.
    pub fn build_store_batch(
        &mut self,
        records: &[messages::BatchedRecord],
    ) -> Option<(u32, Vec<u8>, usize)> {
        let mut used = 1usize; // the record count byte
        let mut taken = 0usize;
        for rec in records.iter().take(messages::MAX_STORE_BATCH_RECORDS) {
            let cost = messages::batched_record_wire_len(rec.record.len());
            if used + cost > messages::MAX_UNFRAGMENTED_PAYLOAD {
                // Stop at the first record that does not fit rather than
                // skipping it: `taken` is a prefix length, and the caller
                // relies on that to line the ack bitmap up with the records
                // it queued. A record too large to ever fit is handled by the
                // caller, which drops that one record and continues.
                break;
            }
            used += cost;
            taken += 1;
        }
        if taken == 0 {
            return None;
        }
        let request_id = self.next_request_id();
        let msg =
            messages::build_store_batch(self.local_id, request_id, records[..taken].to_vec());
        let bytes = messages::encode_message(&msg, &self.signing_key, true);
        Some((request_id, bytes, taken))
    }

    /// Whether a record can ever be carried in a batch at all.
    ///
    /// A single `STORE_RECORD` accepts a larger body than a batch can hold,
    /// so a record between the two limits would stall a batch forever. The
    /// publisher uses this to skip such a record rather than let it block the
    /// ones behind it.
    pub fn record_fits_a_batch(record_len: usize) -> bool {
        /// The leading record-count byte every batch payload carries.
        const COUNT_BYTE: usize = 1;
        COUNT_BYTE + messages::batched_record_wire_len(record_len)
            <= messages::MAX_UNFRAGMENTED_PAYLOAD
    }

    /// Keep a copy of a record we are publishing, when this node is one of
    /// those responsible for its key.
    ///
    /// Kademlia expects a publisher that is itself among the closest nodes to
    /// a key to hold the record like any other storer. Publishing only ever
    /// sends `STORE_RECORD` to *other* contacts, so without this the node that
    /// is often nearest its own keys is the one node guaranteed not to serve
    /// them. On a small network that is fatal: with two peers, each one's
    /// records live exclusively on the other, and neither can answer a
    /// `FIND_VALUE` for what it published itself.
    ///
    /// Returns whether the record was stored (false when we are not
    /// responsible for the key, or the store rejected it).
    ///
    /// Uses the same responsibility test as the inbound `STORE_RECORD` path,
    /// so a publisher holds its own record on exactly the keys it would hold
    /// someone else's.
    pub fn store_own_record(&mut self, record: &SignedRecord) -> bool {
        if !self.store_proximity_ok(&record.keyword_hash) {
            return false;
        }
        self.sync_store_scale();
        self.store.store(
            record.keyword_hash,
            record.data.clone(),
            record.signature,
            record.publisher_key,
            record.timestamp,
        )
    }

    /// Blobs we already hold for `key`, in `FOUND_VALUE` wire form.
    ///
    /// A search only ever queries other nodes, so records in our own store are
    /// invisible to our own lookups. That is wrong at any size — we may be the
    /// closest node to the key — and on a small network it is the difference
    /// between finding everything and finding nothing.
    ///
    /// `extra_keys` applies the same multi-keyword intersection a remote peer
    /// would, so our own store answers a query exactly as another node's
    /// would rather than contributing everything under the primary key and
    /// relying on a downstream filter to clean up.
    pub fn local_records(&self, key: &[u8; 16], extra_keys: &[[u8; 16]]) -> Vec<Vec<u8>> {
        let mut keys = Vec::with_capacity(1 + extra_keys.len());
        keys.push(*key);
        keys.extend_from_slice(extra_keys);
        // Deliberately not `intersect_find_value_records`: that packs to what one
        // datagram can carry, which for typical filenames is about five records.
        // Nothing is being sent here — this is our own store being read to seed a
        // local search — so applying a wire limit to it simply threw away most of
        // the answer, and did so worst on a small network, where this node holds
        // much of the index.
        //
        // How much of a search's result budget this may actually occupy is the
        // searcher's call, not ours: see `MAX_LOCAL_SEED_RESULTS`. The cap here is
        // only so one enormous key cannot hand the caller an unbounded vector.
        intersect_live_records(&self.store, &keys)
            .map(|(_key, records)| {
                records
                    .into_iter()
                    .take(messages::MAX_FOUND_VALUE_RECORDS)
                    .map(record_blob)
                    .collect()
            })
            .unwrap_or_default()
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

    /// Cumulative records the local store refused because it is already
    /// holding its maximum number of distinct keys.
    pub fn store_key_cap_rejections(&self) -> u64 {
        self.store.key_cap_rejections()
    }

    /// Local store stats `(distinct_keys, total_records)` restricted to
    /// records authored by someone else — what this node is genuinely
    /// storing on the network's behalf, as opposed to [`Self::store_stats`],
    /// which also counts a record of our own that happens to have landed in
    /// our own store.
    pub fn foreign_store_stats(&self) -> (usize, usize) {
        self.store.foreign_stats(&self.ed25519_public_key())
    }

    /// Snapshot of live store keys for the diagnostic UI (capped).
    pub fn store_entries(&self, max: usize) -> Vec<DhtStoreEntry> {
        self.store.snapshot(max)
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
    /// than `threshold_secs` (or all, when `force`), capped at `max`.
    ///
    /// Verified contacts and unverified leads draw on separate shares of the
    /// budget. Leads arrive with `last_seen == 0`, so ranking the two together
    /// by staleness placed every lead ahead of every proven contact and left
    /// nothing to refresh the table with: a node that had finished joining
    /// spent its whole budget re-probing gossip while the contacts it actually
    /// routes through aged past the timeout and were evicted.
    ///
    /// Leads keep a reserved minority share and take everything the verified
    /// side does not claim, so a starved table — few verified contacts, many
    /// leads — still spends nearly the whole (deliberately wider) budget
    /// finding out which leads are real.
    pub fn contacts_due_for_ping(
        &self,
        now: i64,
        threshold_secs: i64,
        max: usize,
        force: bool,
    ) -> Vec<EmberContact> {
        if max == 0 {
            return Vec::new();
        }
        let (mut leads, mut verified): (Vec<EmberContact>, Vec<EmberContact>) = self
            .routing
            .all_contacts()
            .into_iter()
            .filter(|c| force || !c.is_verified() || (now - c.last_seen) > threshold_secs)
            .partition(|c| !c.is_verified());

        verified.sort_by_key(|c| c.last_seen); // stalest first
        // Leads have no staleness to rank by, so prefer those we have not
        // already failed against: a wall of dead gossip would otherwise hold
        // the reserve until it faults out, keeping fresh leads unprobed.
        leads.sort_by_key(|c| c.failed_queries);

        let lead_reserve = max.div_ceil(LEAD_PING_RESERVE_DIVISOR).min(leads.len());
        let mut due: Vec<EmberContact> = verified
            .into_iter()
            .take(max - lead_reserve)
            .collect();
        due.extend(leads.into_iter().take(max - due.len()));
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

    /// Records worth carrying across a restart (see
    /// [`DhtStore::persistable`]).
    pub fn persistable_records(&self, max: usize) -> Vec<super::store::PersistedRecord> {
        self.store.persistable(max)
    }

    /// Load persisted records back into the store, returning how many were
    /// accepted (see [`DhtStore::restore`]).
    pub fn restore_records(&mut self, records: Vec<super::store::PersistedRecord>) -> usize {
        self.store.restore(records)
    }

    /// Records waiting to be replicated onward (see
    /// [`DhtStore::republish_backlog`]).
    pub fn republish_backlog(&self, interval: Duration) -> usize {
        self.store.republish_backlog(interval)
    }

    /// Re-arm a record whose republish was never queued (see
    /// [`DhtStore::mark_republish_due`]).
    pub fn mark_republish_due(&mut self, key: &[u8; 16], signature: &[u8; 64]) {
        self.store.mark_republish_due(key, signature);
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
        self.sync_store_scale();

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
                let pong = messages::build_pong(self.local_id, msg.request_id, from);
                out.responses
                    .push(messages::encode_message(&pong, &self.signing_key, true));
            }
            DhtPayload::Pong { observed } => {
                out.pong_received = true;
                out.pong_request_id = Some(msg.request_id);
                out.pong_observed = observed;
                // The PONG proves liveness; refresh the contact's
                // bucket position so it isn't evicted as stale.
                self.routing.mark_alive(&msg.sender_id);
            }
            DhtPayload::FindNode { target } => {
                out.find_node_received = true;
                let closest = self.closest_excluding(&target, msg.sender_id);
                let found = messages::build_found_node(self.local_id, msg.request_id, closest);
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
                Self::merge_gossip_contacts(&mut self.routing, &contacts, &mut out);
                out.found_node = Some((msg.request_id, contacts));
            }
            DhtPayload::StoreRecord {
                key,
                record,
                record_signature,
            } => {
                match self.accept_record(key, record, record_signature, from) {
                    StoreOutcome::Stored => {
                        out.stored_record = true;
                        let ack = messages::build_store_ack(self.local_id, msg.request_id, key);
                        out.responses
                            .push(messages::encode_message(&ack, &self.signing_key, true));
                    }
                    StoreOutcome::Replay => out.store_replay_rejected = true,
                    // A record that fails to parse/verify, whose key does not
                    // match its content, or (for a non-firewalled source)
                    // whose claimed IP doesn't match the sender, is dropped
                    // with no ACK.
                    StoreOutcome::Rejected => {}
                }
            }
            DhtPayload::StoreBatch { records } => {
                // Identical acceptance rules to a single STORE, applied
                // record by record: batching is a framing optimisation and
                // must not become a way to store something a lone STORE
                // could not.
                // Report acceptance per record. The publisher retires a file
                // only when the record carrying it actually landed, so a
                // total would let one accepted record retire the whole batch.
                let mut accepted = 0u64;
                let mut stored = 0u16;
                for (i, rec) in records.into_iter().enumerate() {
                    match self.accept_record(rec.key, rec.record, rec.record_signature, from) {
                        StoreOutcome::Stored => {
                            accepted |= 1u64 << i;
                            stored = stored.saturating_add(1);
                        }
                        StoreOutcome::Replay => {
                            // A replay means we already hold this exact
                            // record, which is what the publisher wanted, so
                            // it counts as placed.
                            accepted |= 1u64 << i;
                            out.store_replay_rejected = true;
                        }
                        StoreOutcome::Rejected => {}
                    }
                }
                out.stored_record = stored > 0;
                out.batch_records_stored = stored;
                // Always answer, even with nothing accepted: the publisher
                // needs to tell "stored nothing" apart from "never arrived"
                // so it can retry rather than assume the records are placed.
                let ack =
                    messages::build_store_batch_ack(self.local_id, msg.request_id, accepted);
                out.responses
                    .push(messages::encode_message(&ack, &self.signing_key, true));
            }
            DhtPayload::StoreBatchAck { accepted } => {
                out.store_batch_ack = Some((msg.request_id, accepted));
            }
            DhtPayload::ProxyStore {
                key,
                record,
                record_signature,
            } => {
                // Buddy-assisted publish: a firewalled peer asks us to fan
                // out their already-signed source record. We verify it and
                // bind the requester to the publisher identity
                // (`sender_id == BLAKE3(publisher_key)`) so a third party
                // cannot amplify someone else's record. ACK is deferred to
                // the network loop until `start_publish` actually starts.
                if let Some(parsed) = SignedRecord::from_wire(&record, record_signature) {
                    let is_fw_source = parsed.record_type == RECORD_TYPE_SOURCE
                        && parsed
                            .source_contact
                            .map(|sc| sc.flags & SOURCE_FLAG_FIREWALLED != 0)
                            .unwrap_or(false);
                    let publisher_is_sender = crypto::node_id_from_ed25519_bytes(
                        &parsed.publisher_key,
                    )
                    .map(|id| EmberNodeId(id) == msg.sender_id)
                    .unwrap_or(false);
                    if is_fw_source && key == parsed.keyword_hash && publisher_is_sender {
                        out.proxy_store_forward = Some((msg.request_id, parsed));
                    }
                }
            }
            DhtPayload::AnnouncePeer { contacts } => {
                // Peer-list exchange (bootstrap-style gossip): merge the
                // asker's dump, then reply with our closest contacts to
                // the asker so both tables thicken without a FIND_NODE.
                out.announce_peer_received = true;
                Self::merge_gossip_contacts(&mut self.routing, &contacts, &mut out);
                let closest = self.closest_excluding(&msg.sender_id, msg.sender_id);
                let peer_list =
                    messages::build_peer_list(self.local_id, msg.request_id, closest);
                out.responses
                    .push(messages::encode_message(&peer_list, &self.signing_key, true));
            }
            DhtPayload::PeerList { contacts } => {
                Self::merge_gossip_contacts(&mut self.routing, &contacts, &mut out);
                out.peer_list = Some((msg.request_id, contacts));
            }
            DhtPayload::ProxyStoreAck { key: _ } => {
                // Publisher-side: buddy accepted the proxy request. No
                // further engine work — diagnostics are updated by the
                // network loop if desired.
            }
            DhtPayload::FindValue { keys } => {
                out.find_value_received = true;
                // Multi-keyword wire intersection (when `keys.len() > 1`):
                // serve primary-key (`keys[0]`) records; when this node also
                // holds secondary keys, filter by `file_hash` intersection.
                // Missing secondaries are skipped (sparse DHT locality) —
                // filename AND at emit remains the cross-key filter.
                if let Some(reply) = intersect_find_value_records(&self.store, &keys) {
                    out.find_value_hit = true;
                    out.find_value_withheld = reply.withheld.min(u16::MAX as usize) as u16;
                    let fv = messages::build_found_value(
                        self.local_id,
                        msg.request_id,
                        reply.key,
                        reply.blobs,
                    );
                    out.responses
                        .push(messages::encode_message(&fv, &self.signing_key, true));
                } else {
                    let target = keys
                        .first()
                        .map(|k| EmberNodeId(*k))
                        .unwrap_or(self.local_id);
                    // Exclude the asker, like the FIND_NODE and ANNOUNCE_PEER
                    // paths. `handle_message` adds the sender to the table
                    // before we get here, so a bare `find_closest` could spend
                    // one of only twenty slots telling a peer about itself.
                    let closest = self.closest_excluding(&target, msg.sender_id);
                    let found = messages::build_found_node(self.local_id, msg.request_id, closest);
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
                // Unknown arrive here once peers speak them. We've already
                // learned the sender above.
                trace!(
                    "Ember DHT: ignoring unhandled message type from {from}: {:?}",
                    std::mem::discriminant(&other)
                );
            }
        }

        out
    }

    /// Merge unverified gossip contacts from a signed peer frame into the
    /// routing table, collecting any full-bucket liveness checks.
    fn merge_gossip_contacts(
        routing: &mut RoutingTable,
        contacts: &[EmberContact],
        out: &mut DhtInbound,
    ) {
        for contact in contacts {
            if let AddResult::PingOldest {
                addr,
                node_id,
                noise_pub,
            } = routing.add_contact(contact.clone())
            {
                out.ping_oldest.push((addr, node_id, noise_pub));
            }
        }
    }
}

/// Extract `file_hash` from a packed Ember DHT record (`type || keyword_hash || file_hash || …`).
fn file_hash_from_record_data(data: &[u8]) -> Option<[u8; 16]> {
    if data.len() < 33 {
        return None;
    }
    let mut h = [0u8; 16];
    h.copy_from_slice(&data[17..33]);
    Some(h)
}

/// Multi-keyword FIND_VALUE answer: primary-key blobs whose `file_hash`
/// appears under every secondary key this node also holds.
///
/// Secondary keywords live near different IDs on a sparse DHT, so the
/// peer closest to the primary often holds none of the extras. Missing
/// secondaries are skipped (not treated as empty intersection) so we
/// still serve primary hits; the searcher applies filename AND at emit
/// as defense-in-depth. When we *do* hold one or more secondaries, we
/// filter by `file_hash` intersection. Empty intersection → `None`
/// (`FOUND_NODE`). Single-key queries serve all live primary records.
fn intersect_find_value_records(store: &DhtStore, keys: &[[u8; 16]]) -> Option<FoundValueReply> {
    let (primary, filtered) = intersect_live_records(store, keys)?;

    // Pack records until the reply would stop fitting a datagram. A key can
    // legitimately hold far more records than one response can carry, and an
    // oversized reply is dropped undecrypted by the receiver, so the node
    // holding the most records for a popular key would otherwise be the one
    // node that can never answer for it. A partial answer is always better:
    // the searcher merges results across the peers it walks.
    let mut used = 0usize;
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    for r in &filtered {
        if blobs.len() >= messages::MAX_FOUND_VALUE_RECORDS {
            break;
        }
        let cost = 2 + r.data.len() + 64;
        if used + cost > messages::MAX_FOUND_VALUE_RECORD_BYTES {
            // Records vary in size, so keep scanning for a smaller one that
            // still fits rather than stopping at the first oversized record.
            continue;
        }
        used += cost;
        blobs.push(record_blob(r));
    }

    if blobs.is_empty() {
        return None;
    }
    let withheld = filtered.len() - blobs.len();
    Some(FoundValueReply {
        key: primary,
        blobs,
        withheld,
    })
}

/// A `FOUND_VALUE` answer plus what the datagram had no room for.
struct FoundValueReply {
    key: [u8; 16],
    blobs: Vec<Vec<u8>>,
    /// Live matching records left unserved by this reply.
    withheld: usize,
}

/// `record_data || signature`, the shape a `FOUND_VALUE` blob and a locally
/// seeded record both take.
fn record_blob(record: &super::store::DhtRecord) -> Vec<u8> {
    let mut b = Vec::with_capacity(record.data.len() + 64);
    b.extend_from_slice(&record.data);
    b.extend_from_slice(&record.signature);
    b
}

/// The live records under `keys[0]` whose file hash also appears under every
/// other key, with no packing applied.
///
/// Split out from [`intersect_find_value_records`] so a caller reading its own
/// store does not inherit a limit that exists only because a reply has to fit in
/// one datagram — see [`EmberDht::local_records`].
fn intersect_live_records<'a>(
    store: &'a DhtStore,
    keys: &[[u8; 16]],
) -> Option<([u8; 16], Vec<&'a super::store::DhtRecord>)> {
    let primary = *keys.first()?;
    let primary_recs = store.get_live(&primary);
    if primary_recs.is_empty() {
        return None;
    }

    let mut allowed: Option<HashSet<[u8; 16]>> = None;
    for key in keys.iter().skip(1) {
        let secondary = store.get_live(key);
        if secondary.is_empty() {
            continue;
        }
        let hashes: HashSet<[u8; 16]> = secondary
            .iter()
            .filter_map(|r| file_hash_from_record_data(&r.data))
            .collect();
        allowed = Some(match allowed {
            None => hashes,
            Some(prev) => prev.intersection(&hashes).copied().collect(),
        });
    }

    let filtered: Vec<&_> = match &allowed {
        None => primary_recs,
        Some(set) => primary_recs
            .into_iter()
            .filter(|r| {
                file_hash_from_record_data(&r.data)
                    .map(|h| set.contains(&h))
                    .unwrap_or(false)
            })
            .collect(),
    };

    // Applied an AND and nothing survived → FOUND_NODE so the searcher
    // keeps walking (we are not a useful value peer for this query).
    if filtered.is_empty() {
        return None;
    }
    Some((primary, filtered))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dht(seed: u8) -> EmberDht {
        EmberDht::new([seed; 32], false)
    }

    fn addr(last: u8, port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, last], port))
    }

    /// A contact that lands in bucket `bucket` — one bit of XOR distance from
    /// us — in its own /24. Both matter: a k-bucket holds only
    /// [`K_BUCKET_SIZE`] contacts, and subnet diversity refuses crowding, so
    /// contacts minted from a running counter would mostly never be admitted.
    fn contact_in_bucket(local: EmberNodeId, bucket: usize, last_seen: i64) -> EmberContact {
        let mut id = local.0;
        id[15 - bucket / 8] ^= 1 << (bucket % 8);
        let b = bucket as u8;
        EmberContact {
            node_id: EmberNodeId(id),
            addr: SocketAddr::from(([80, 1, b.wrapping_add(1), 1], 4672)),
            noise_pub: [b; 32],
            ed25519_pub: [b; 32],
            last_seen,
            failed_queries: 0,
        }
    }

    /// Gossip and on-disk contacts arrive with `last_seen == 0`. Ranking them
    /// against proven contacts by staleness put every one of them first, so a
    /// joined node spent its entire ping budget re-probing leads while the
    /// contacts it routes through aged out.
    #[test]
    fn leads_cannot_crowd_verified_contacts_out_of_the_ping_budget() {
        let mut d = dht(11);
        let local = d.local_id();
        let now = 100_000i64;
        // Stale enough to be due, and far more leads than the budget.
        for bucket in 0..6 {
            assert!(d.add_contact(contact_in_bucket(local, bucket, now - 5_000)));
        }
        for bucket in 10..51 {
            assert!(d.add_contact(contact_in_bucket(local, bucket, 0)));
        }

        let due = d.contacts_due_for_ping(now, 600, 8, false);
        assert_eq!(due.len(), 8, "the whole budget should be spent");

        let verified = due.iter().filter(|c| c.is_verified()).count();
        assert_eq!(
            verified, 6,
            "every due verified contact must be pinged before leads take the rest"
        );
        assert_eq!(due.len() - verified, 2, "leads keep only their reserve");
    }

    /// The reserve is a floor for leads, not a ceiling: while the table is
    /// starved there are few verified contacts to spend the (deliberately
    /// wider) budget on, and it should go to finding out which leads are real.
    #[test]
    fn a_starved_table_still_spends_its_budget_on_leads() {
        let mut d = dht(12);
        let local = d.local_id();
        let now = 100_000i64;
        assert!(d.add_contact(contact_in_bucket(local, 0, now - 5_000)));
        for bucket in 10..51 {
            assert!(d.add_contact(contact_in_bucket(local, bucket, 0)));
        }

        let due = d.contacts_due_for_ping(now, 600, 32, false);
        assert_eq!(due.len(), 32);
        assert_eq!(
            due.iter().filter(|c| !c.is_verified()).count(),
            31,
            "the one verified contact aside, the budget should go to leads"
        );
    }

    /// A verified contact still inside the freshness window is not due, so it
    /// must not consume budget that a lead could use.
    #[test]
    fn fresh_verified_contacts_are_not_due_for_a_ping() {
        let mut d = dht(13);
        let local = d.local_id();
        let now = 100_000i64;
        for bucket in 0..6 {
            assert!(d.add_contact(contact_in_bucket(local, bucket, now - 10)));
        }
        for bucket in 10..16 {
            assert!(d.add_contact(contact_in_bucket(local, bucket, 0)));
        }

        let due = d.contacts_due_for_ping(now, 600, 8, false);
        assert!(
            due.iter().all(|c| !c.is_verified()),
            "only the leads are due"
        );
        assert_eq!(due.len(), 6, "and there are only six of them");
    }

    /// Dead gossip accumulates failures before eviction; it must not hold the
    /// lead reserve against leads we have never tried.
    #[test]
    fn untried_leads_are_probed_before_ones_already_failing() {
        let mut d = dht(14);
        let local = d.local_id();
        let now = 100_000i64;
        for bucket in 10..21 {
            let mut c = contact_in_bucket(local, bucket, 0);
            c.failed_queries = 2;
            assert!(d.add_contact(c));
        }
        let fresh = contact_in_bucket(local, 30, 0);
        assert!(d.add_contact(fresh.clone()));

        let due = d.contacts_due_for_ping(now, 600, 4, false);
        assert!(
            due.iter().any(|c| c.node_id == fresh.node_id),
            "an untried lead must outrank ones that have already missed"
        );
    }

    /// Publishing sends `STORE_RECORD` only to *other* contacts, so a node
    /// that is itself responsible for a key used to be the one node that
    /// could not answer a `FIND_VALUE` for its own record. With two peers
    /// that means each one's records live solely on the other, and neither
    /// side's search finds anything — which is exactly what a two-node test
    /// produced before this.
    #[test]
    fn a_publisher_serves_its_own_record() {
        let mut d = dht(3);
        let record = d.build_keyword_record("holiday", [0x11; 16], [0x22; 32], 4096, "holiday.mkv");
        let key = record.keyword_hash;

        assert!(d.local_records(&key, &[]).is_empty(), "nothing stored yet");
        assert!(d.store_own_record(&record), "we are responsible for this key");

        let held = d.local_records(&key, &[]);
        assert_eq!(held.len(), 1);
        let mut expected = record.data.clone();
        expected.extend_from_slice(&record.signature);
        assert_eq!(held[0], expected, "served blob must be FOUND_VALUE-shaped");
    }

    /// The stored blob has to survive the same parse a searcher runs on
    /// anything that arrives over the wire, or seeding a search from the
    /// local store would hand it records it then silently discards.
    #[test]
    fn a_locally_served_record_round_trips_through_the_wire_parser() {
        let mut d = dht(4);
        let record = d.build_keyword_record("ember", [0xAB; 16], [0xCD; 32], 1234, "ember.iso");
        assert!(d.store_own_record(&record));

        let blob = d.local_records(&record.keyword_hash, &[]).remove(0);
        let parsed = SignedRecord::from_value_blob(&blob).expect("blob must re-verify");
        assert_eq!(
            parsed.record_type,
            super::super::publish::RECORD_TYPE_KEYWORD
        );
        assert_eq!(parsed.keyword_hash, record.keyword_hash);
        assert_eq!(parsed.file_hash, [0xAB; 16]);
        assert_eq!(parsed.file_name, "ember.iso");
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
        assert_eq!(
            on_a.pong_request_id,
            Some(rid),
            "PONG must echo A's request id"
        );
        assert_eq!(
            on_a.pong_observed,
            Some(a_addr),
            "PONG must echo the observed sender addr"
        );
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
    fn announce_peer_exchanges_lists_and_learns_contacts() {
        let mut a = dht(20);
        let mut b = dht(21);
        let a_noise = [0xAA; 32];
        let b_noise = [0xBB; 32];
        let a_addr = addr(20, 4672);
        let b_addr = addr(21, 4672);

        let c = dht(22);
        let c_contact = EmberContact {
            node_id: c.local_id(),
            addr: addr(22, 4672),
            noise_pub: [0xCC; 32],
            ed25519_pub: c.ed25519_public_key(),
            last_seen: 500,
            failed_queries: 0,
        };
        assert!(b.add_contact(c_contact.clone()));

        // A announces an empty dump; B merges nothing extra but replies
        // with its closest (including C).
        let (rid, announce) = a.build_announce_peer(Vec::new());
        let on_b = b.handle_message(&announce, a_addr, a_noise, 1000);
        assert!(on_b.announce_peer_received);
        assert_eq!(on_b.responses.len(), 1);
        assert!(on_b.learned_contact);

        let on_a = a.handle_message(&on_b.responses[0], b_addr, b_noise, 1001);
        let (got_rid, contacts) = on_a.peer_list.expect("PEER_LIST");
        assert_eq!(got_rid, rid);
        assert!(
            contacts.iter().any(|x| x.node_id == c.local_id()),
            "B should have returned C in PEER_LIST"
        );
        assert!(
            a.contacts().iter().any(|x| x.node_id == c.local_id()),
            "A should learn C from PEER_LIST"
        );

        // Reverse direction: A knows D, announces it to B.
        let d = dht(23);
        let d_contact = EmberContact {
            node_id: d.local_id(),
            addr: addr(23, 4672),
            noise_pub: [0xDD; 32],
            ed25519_pub: d.ed25519_public_key(),
            last_seen: 0,
            failed_queries: 0,
        };
        assert!(a.add_contact(d_contact.clone()));
        let (_rid2, announce2) = a.build_announce_peer(vec![d_contact.clone()]);
        let on_b2 = b.handle_message(&announce2, a_addr, a_noise, 2000);
        assert!(
            b.contacts().iter().any(|x| x.node_id == d.local_id()),
            "B should learn D from ANNOUNCE_PEER gossip"
        );
        assert!(on_b2.announce_peer_received);
        let _ = c_contact;
    }

    #[test]
    fn handle_message_fuzz_never_panics() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xA11C_E11E);
        let mut engine = dht(90);
        let from = addr(90, 4672);
        let noise = [0xEE; 32];
        for _ in 0..1_000 {
            let len = rng.gen_range(0..=1_024);
            let mut buf = vec![0u8; len];
            rng.fill(&mut buf[..]);
            let _ = engine.handle_message(&buf, from, noise, 1_000);
        }
    }

    #[test]
    fn routing_churn_soak_add_evict_stable() {
        let mut engine = dht(91);
        // Flood the table with many distinct contacts, then mark failures
        // until some evict — must not panic or corrupt contact_count.
        for i in 0u16..256 {
            let mut ed = [0u8; 32];
            ed[0] = (i >> 8) as u8;
            ed[1] = i as u8;
            ed[2] = 0x91;
            // Derive a plausible node_id from a synthetic keying scheme:
            // use blake3 of ed for id so add_contact accepts the binding.
            let id_bytes = blake3::hash(&ed);
            let mut node = [0u8; 16];
            node.copy_from_slice(&id_bytes.as_bytes()[..16]);
            let contact = EmberContact {
                node_id: EmberNodeId(node),
                addr: addr((i % 250) as u8 + 1, 4000 + i),
                noise_pub: {
                    let mut n = [0u8; 32];
                    n[0] = i as u8;
                    n[1] = 0x42;
                    n
                },
                ed25519_pub: ed,
                last_seen: i as i64,
                failed_queries: 0,
            };
            let _ = engine.add_contact(contact);
        }
        let before = engine.contact_count();
        assert!(before > 0);
        let snapshot: Vec<_> = engine.contacts().into_iter().map(|c| c.node_id).collect();
        for id in snapshot.iter().take(snapshot.len() / 2) {
            for _ in 0..8 {
                if engine.mark_failed_contact(id) {
                    let _ = engine.evict_contact(id);
                    break;
                }
            }
        }
        assert!(engine.contact_count() <= before);
    }

    /// Batching is a framing change only: many records reach a peer in one
    /// datagram, and each is subject to exactly the checks a lone STORE would
    /// apply.
    #[test]
    fn a_store_batch_stores_every_record_and_fits_one_datagram() {
        let mut a = dht(30);
        let mut b = dht(31);
        let a_noise = [0xAA; 32];
        let b_noise = [0xBB; 32];
        let a_addr = addr(30, 4672);
        let b_addr = addr(31, 4672);

        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let records: Vec<messages::BatchedRecord> = (0..12u8)
            .map(|i| {
                let rec = SignedRecord::keyword(
                    &format!("word{i}"),
                    [i; 16],
                    [0u8; 32],
                    100,
                    "a-release-name.iso",
                    &sk,
                );
                messages::BatchedRecord {
                    key: rec.keyword_hash,
                    record: rec.data.clone(),
                    record_signature: rec.signature,
                }
            })
            .collect();

        // Drain the way the publisher does: as many datagrams as the byte
        // budget requires, each one deliverable on its own.
        let mut remaining = records.clone();
        let mut frames = 0;
        let mut acked_total = 0usize;
        while !remaining.is_empty() {
            let (rid, frame, taken) = a.build_store_batch(&remaining).expect("a batch");
            assert!(taken > 0, "each batch must make progress");
            assert!(
                frame.len() + messages::TRANSPORT_OVERHEAD
                    <= messages::MAX_UNFRAGMENTED_DATAGRAM,
                "a batch must not fragment"
            );
            frames += 1;

            let on_b = b.handle_message(&frame, a_addr, a_noise, 1000 + frames);
            assert_eq!(on_b.batch_records_stored as usize, taken);
            assert_eq!(on_b.responses.len(), 1, "exactly one ack per batch");

            let on_a = a.handle_message(&on_b.responses[0], b_addr, b_noise, 2000 + frames);
            let (ack_rid, accepted) = on_a.store_batch_ack.expect("ack decodes");
            assert_eq!(ack_rid, rid);
            // The ack names the accepted records positionally, so the set
            // bits must be exactly the batch's records and no others.
            assert_eq!(
                accepted.count_ones() as usize,
                taken,
                "every record in this batch was stored, so every bit is set"
            );
            assert_eq!(
                accepted >> taken,
                0,
                "no bit may be set past the batch's record count"
            );
            acked_total += accepted.count_ones() as usize;

            remaining.drain(..taken);
        }
        assert!(frames > 1, "twelve records exceed one datagram");
        assert_eq!(acked_total, records.len());
        assert_eq!(b.store_stats().1, records.len());

        // Every record is individually retrievable, so batching did not merge
        // or lose any of them.
        for rec in &records {
            let (_frid, find) = a.build_find_value(vec![rec.key]);
            let hit = b.handle_message(&find, a_addr, a_noise, 1002);
            assert!(hit.find_value_hit, "each batched key must be servable");
        }
    }

    /// A batch that overflows one datagram is split rather than sent whole
    /// and silently dropped by the peer.
    #[test]
    fn an_oversized_batch_is_split_across_datagrams() {
        let mut a = dht(32);
        let sk = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);
        let long_name = "x".repeat(200);
        let records: Vec<messages::BatchedRecord> = (0..40u8)
            .map(|i| {
                let rec =
                    SignedRecord::keyword(&format!("w{i}"), [i; 16], [0u8; 32], 1, &long_name, &sk);
                messages::BatchedRecord {
                    key: rec.keyword_hash,
                    record: rec.data.clone(),
                    record_signature: rec.signature,
                }
            })
            .collect();

        let (_rid, frame, taken) = a.build_store_batch(&records).expect("a batch");
        assert!(taken < records.len(), "the batch must be split");
        assert!(taken > 0, "and must still make progress");
        assert!(
            frame.len() + messages::TRANSPORT_OVERHEAD <= messages::MAX_UNFRAGMENTED_DATAGRAM
        );
    }

    /// Responsibility is "am I among the k closest I know of", not a fixed
    /// half of the key space. A node that knows fewer than k contacts is
    /// among the k closest to everything, so it must hold every key — the old
    /// half-space rule discarded about half of them on a coin flip.
    #[test]
    fn a_sparse_node_is_responsible_for_every_key() {
        let mut d = dht(3);
        for i in 0..256u32 {
            let keyword = format!("keyword{i}");
            let key = crate::network::ember::dht::search::keyword_hash(&keyword);
            let record = d.build_keyword_record(&keyword, [1u8; 16], [0u8; 32], 10, "f.iso");
            assert_eq!(record.keyword_hash, key);
            assert!(
                d.store_own_record(&record),
                "a node knowing no contacts must hold {keyword}, on either side of its ID"
            );
            assert!(!d.local_records(&key, &[]).is_empty());
        }
    }

    /// With a full table, a key that k known nodes are all closer to is not
    /// ours to hold.
    #[test]
    fn a_well_connected_node_declines_keys_it_is_far_from() {
        let mut d = dht(4);
        let local = d.local_id();

        // Fill the table with contacts clustered around a far corner of the
        // key space, so keys near them are better served by them than by us.
        // Distinct /24s so the routing table's diversity caps admit them all.
        for i in 0..(K_BUCKET_SIZE as u8 + 4) {
            let mut id = [0xFFu8; 16];
            id[15] = i;
            let contact = EmberContact {
                node_id: EmberNodeId(id),
                addr: SocketAddr::from(([80, i, 1, 1], 4672)),
                noise_pub: [i; 32],
                ed25519_pub: [i; 32],
                last_seen: chrono::Utc::now().timestamp(),
                failed_queries: 0,
            };
            let _ = d.add_contact(contact);
        }
        assert!(
            d.routing.find_closest(&EmberNodeId([0xFF; 16]), K_BUCKET_SIZE).len()
                >= K_BUCKET_SIZE,
            "the table needs k contacts for proximity gating to engage"
        );

        // A key sitting right on that cluster: those contacts are all much
        // closer to it than we are.
        let mut far_key = [0xFFu8; 16];
        far_key[15] = 0x01;
        assert!(
            !d.store_proximity_ok(&far_key),
            "a key k closer nodes cover is not ours to hold"
        );
        // A key adjacent to our own ID is still ours.
        assert!(d.store_proximity_ok(&local.0));
    }

    #[test]
    fn a_full_found_value_frame_fits_a_datagram() {
        // A key holding far more records than one reply can carry must still
        // produce a deliverable answer. An oversized datagram is discarded by
        // the receiver before decryption, so the sender sees a clean send and
        // the searcher sees only a timeout.
        let mut a = dht(26);
        let mut b = dht(27);
        let a_noise = [0xAA; 32];
        let a_addr = addr(26, 4672);

        let probe = a.build_keyword_record("linux", [0u8; 16], [0u8; 32], 1, "x.iso");
        let key = probe.keyword_hash;

        // Many distinct publishers, each with a long file name, all under one
        // key — the shape a popular keyword takes on a healthy network.
        let name = "a-fairly-long-release-file-name-for-sizing.iso";
        for i in 0..80u8 {
            let sk = ed25519_dalek::SigningKey::from_bytes(&[i.wrapping_add(1); 32]);
            let rec = SignedRecord::keyword("linux", [i; 16], [0u8; 32], 1, name, &sk);
            assert_eq!(rec.keyword_hash, key);
            assert!(b.store.store(
                key,
                rec.data.clone(),
                rec.signature,
                rec.publisher_key,
                rec.timestamp,
            ));
        }

        let (_frid, find_bytes) = a.build_find_value(vec![key]);
        let on_b = b.handle_message(&find_bytes, a_addr, a_noise, 1000);
        assert!(on_b.find_value_hit, "the key is held and must be answered");
        assert_eq!(on_b.responses.len(), 1);

        let frame = &on_b.responses[0];
        let datagram = frame.len() + messages::TRANSPORT_OVERHEAD;
        assert!(
            datagram <= crate::network::ember::transport::MAX_EMBER_DATAGRAM_BYTES,
            "FOUND_VALUE datagram would be {datagram} bytes, over the transport cap"
        );

        // And it still round-trips with real records in it.
        let on_a = a.handle_message(frame, addr(27, 4672), [0xBB; 32], 1001);
        let (_rid, blobs) = on_a.found_value.expect("A should see a FOUND_VALUE");
        assert!(!blobs.is_empty(), "a partial answer, not an empty one");
        assert!(
            blobs.len() < 80,
            "the reply must be trimmed, not carry all 80"
        );

        // But that trimming belongs to the wire. Reading our own store for a local
        // search is not sending anything, and applying the datagram budget to it
        // threw away most of the answer — worst on a small network, where this node
        // holds much of the index and the local read *is* the search.
        let local = b.local_records(&key, &[]);
        assert_eq!(
            local.len(),
            80,
            "a local read must return everything the store holds, not one datagram's worth"
        );
        assert!(
            local.len() > blobs.len() * 4,
            "and the gap between the two is the whole point of the split"
        );
    }

    #[test]
    fn an_over_long_find_value_still_gets_answered() {
        // A peer rejects a FIND_VALUE carrying more than MAX_FIND_VALUE_KEYS
        // at decode and sends nothing back, so a long multi-keyword query
        // would otherwise go unanswered by every node it reached.
        let mut a = dht(24);
        let mut b = dht(25);
        let a_noise = [0xAA; 32];
        let a_addr = addr(24, 4672);

        let record = a.build_keyword_record("ubuntu", [9u8; 16], [0u8; 32], 4096, "ubuntu.iso");
        let key = record.keyword_hash;
        let (_rid, store_bytes) = a.build_store(key, record.data.clone(), record.signature);
        assert!(b.handle_message(&store_bytes, a_addr, a_noise, 1000).stored_record);

        let mut keys = vec![key];
        for i in 0..(messages::MAX_FIND_VALUE_KEYS as u8 + 4) {
            keys.push([i; 16]);
        }
        let (_frid, find_bytes) = a.build_find_value(keys);

        let on_b = b.handle_message(&find_bytes, a_addr, a_noise, 1001);
        assert!(
            on_b.find_value_received,
            "peer must be able to decode the request"
        );
        assert!(
            on_b.find_value_hit,
            "the primary key survives truncation and still hits"
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

    /// A node holding more records under one keyword than a datagram can carry
    /// serves the front of the list and drops the rest. How often that happens
    /// is what separates "few results because the network is small" from "few
    /// results because every answer is capped", so the shortfall has to leave
    /// the engine rather than staying a local variable.
    #[test]
    fn a_truncated_found_value_reports_what_it_could_not_carry() {
        let mut a = dht(20); // publisher / searcher
        let mut b = dht(21); // storer
        let a_noise = [0xAA; 32];
        let b_noise = [0xBB; 32];
        let a_addr = addr(20, 4672);
        let b_addr = addr(21, 4672);

        const PUBLISHED: usize = 20;
        let mut key = [0u8; 16];
        for i in 0..PUBLISHED {
            let mut file_hash = [0u8; 16];
            file_hash[0] = i as u8;
            let record = a.build_keyword_record(
                "ubuntu",
                file_hash,
                [0u8; 32],
                4096,
                &format!("ubuntu-server-22.04.{i:02}-amd64-live.iso"),
            );
            key = record.keyword_hash;
            let (_rid, bytes) = a.build_store(key, record.data.clone(), record.signature);
            assert!(
                b.handle_message(&bytes, a_addr, a_noise, 1000).stored_record,
                "record {i} should be accepted"
            );
        }
        assert_eq!(b.store_stats(), (1, PUBLISHED));

        let (_frid, find_bytes) = a.build_find_value(vec![key]);
        let on_b = b.handle_message(&find_bytes, a_addr, a_noise, 1001);
        assert!(on_b.find_value_hit);
        assert!(
            on_b.find_value_withheld > 0,
            "20 records of this size cannot fit one datagram"
        );

        let on_a = a.handle_message(&on_b.responses[0], b_addr, b_noise, 1002);
        let (_rid, blobs) = on_a.found_value.expect("FOUND_VALUE");
        assert!(
            blobs.len() < PUBLISHED,
            "the reply is bounded by what one datagram carries"
        );
        assert_eq!(
            blobs.len() + on_b.find_value_withheld as usize,
            PUBLISHED,
            "every live record is either served or counted as withheld"
        );
    }

    #[test]
    fn find_value_intersects_multi_keyword_by_file_hash() {
        let mut a = dht(30);
        let mut b = dht(31);
        let mut c = dht(32); // second publisher (store dedupes by publisher key)
        let a_noise = [0xAA; 32];
        let c_noise = [0xCC; 32];
        let b_noise = [0xBB; 32];
        let a_addr = addr(30, 4672);
        let c_addr = addr(32, 4672);
        let b_addr = addr(31, 4672);

        let both = [1u8; 16];
        let only_ubuntu = [2u8; 16];
        let r_both_u = a.build_keyword_record("ubuntu", both, [0u8; 32], 100, "ubuntu-server.iso");
        let r_both_s = a.build_keyword_record("server", both, [0u8; 32], 100, "ubuntu-server.iso");
        let r_only = c.build_keyword_record("ubuntu", only_ubuntu, [0u8; 32], 50, "ubuntu.iso");

        for rec in [&r_both_u, &r_both_s] {
            let (_rid, bytes) = a.build_store(rec.keyword_hash, rec.data.clone(), rec.signature);
            assert!(
                b.handle_message(&bytes, a_addr, a_noise, 1000)
                    .stored_record
            );
        }
        {
            let (_rid, bytes) =
                c.build_store(r_only.keyword_hash, r_only.data.clone(), r_only.signature);
            assert!(
                b.handle_message(&bytes, c_addr, c_noise, 1000)
                    .stored_record
            );
        }

        let (_frid, find_bytes) =
            a.build_find_value(vec![r_both_u.keyword_hash, r_both_s.keyword_hash]);
        let on_b = b.handle_message(&find_bytes, a_addr, a_noise, 1001);
        assert!(on_b.find_value_hit, "peer holds primary+secondary keys");
        let on_a = a.handle_message(&on_b.responses[0], b_addr, b_noise, 1002);
        let (_rid, blobs) = on_a.found_value.expect("FOUND_VALUE");
        assert_eq!(blobs.len(), 1, "only file_hash present under both keys");
        let parsed = SignedRecord::from_value_blob(&blobs[0]).unwrap();
        assert_eq!(parsed.file_hash, both);
        assert_eq!(parsed.file_name, "ubuntu-server.iso");
    }

    #[test]
    fn find_value_serves_primary_when_secondary_not_held() {
        // Sparse DHT: peer near "ubuntu" does not hold "server". It must
        // still return primary hits (filename AND filters at the searcher).
        let mut a = dht(33);
        let mut b = dht(34);
        let a_noise = [0xAA; 32];
        let b_noise = [0xBB; 32];
        let a_addr = addr(33, 4672);
        let b_addr = addr(34, 4672);

        let rec = a.build_keyword_record("ubuntu", [9u8; 16], [0u8; 32], 10, "ubuntu.iso");
        let (_rid, store_bytes) =
            a.build_store(rec.keyword_hash, rec.data.clone(), rec.signature);
        assert!(b.handle_message(&store_bytes, a_addr, a_noise, 1000).stored_record);

        let secondary = a.build_keyword_record("server", [9u8; 16], [0u8; 32], 10, "ubuntu.iso");
        let (_frid, find_bytes) =
            a.build_find_value(vec![rec.keyword_hash, secondary.keyword_hash]);
        let on_b = b.handle_message(&find_bytes, a_addr, a_noise, 1001);
        assert!(
            on_b.find_value_hit,
            "missing secondary must not suppress primary FOUND_VALUE"
        );
        let on_a = a.handle_message(&on_b.responses[0], b_addr, b_noise, 1002);
        let (_rid, blobs) = on_a.found_value.expect("FOUND_VALUE");
        assert_eq!(blobs.len(), 1);
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
        assert!(
            on_b.stored_record,
            "B should accept a source record from A's own IP"
        );
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
        assert!(
            !on_b.stored_record,
            "claimed IP != sender IP must be rejected"
        );
        assert!(
            on_b.responses.is_empty(),
            "no STORE_ACK on reflection rejection"
        );
        assert_eq!(b.store_stats(), (0, 0));
    }

    #[test]
    fn firewalled_source_store_allows_ip_mismatch() {
        let mut a = dht(70);
        let mut b = dht(71);
        let a_noise = [0xAA; 32];
        // Observed sender IP differs from claimed contact IP (buddy path /
        // symmetric NAT). FIREWALLED exempts anti-reflection.
        let a_addr = addr(30, 4672);
        let mut contact = source_contact_at(99);
        contact.flags = crate::network::ember::SOURCE_FLAG_FIREWALLED;
        let record = a.build_source_record([9u8; 16], [0u8; 32], 10, "fw.mkv", contact);
        let key = record.keyword_hash;
        let (_rid, store_bytes) = a.build_store(key, record.data.clone(), record.signature);
        let on_b = b.handle_message(&store_bytes, a_addr, a_noise, 1000);
        assert!(
            on_b.stored_record,
            "FIREWALLED source must store despite IP mismatch"
        );
        assert_eq!(on_b.responses.len(), 1);
    }

    #[test]
    fn proxy_store_forwards_firewalled_source() {
        let mut publisher = dht(80);
        let mut buddy = dht(81);
        let pub_noise = [0xAA; 32];
        let pub_addr = addr(80, 4672);

        let mut contact = source_contact_at(80);
        contact.flags = crate::network::ember::SOURCE_FLAG_FIREWALLED
            | crate::network::ember::SOURCE_FLAG_RELAY_CAPABLE;
        let record =
            publisher.build_source_record([3u8; 16], [0u8; 32], 42, "buddy.mkv", contact);
        let key = record.keyword_hash;
        let (_rid, frame) =
            publisher.build_proxy_store(key, record.data.clone(), record.signature);
        let on_buddy = buddy.handle_message(&frame, pub_addr, pub_noise, 2000);
        assert!(
            on_buddy.proxy_store_forward.is_some(),
            "buddy should accept PROXY_STORE"
        );
        // ACK is deferred until the network loop starts the publish.
        assert!(
            on_buddy.responses.is_empty(),
            "PROXY_STORE_ACK deferred to caller"
        );
        let (rid, fwd) = on_buddy.proxy_store_forward.unwrap();
        assert_ne!(rid, 0);
        assert_eq!(fwd.file_name, "buddy.mkv");
        assert_eq!(fwd.keyword_hash, key);
    }

    #[test]
    fn proxy_store_rejects_non_publisher_sender() {
        let publisher = dht(84);
        let mut impostor = dht(85);
        let mut buddy = dht(86);
        let impostor_noise = [0xBB; 32];
        let impostor_addr = addr(85, 4672);

        let mut contact = source_contact_at(84);
        contact.flags = crate::network::ember::SOURCE_FLAG_FIREWALLED
            | crate::network::ember::SOURCE_FLAG_RELAY_CAPABLE;
        let record =
            publisher.build_source_record([5u8; 16], [0u8; 32], 7, "stolen.mkv", contact);
        let key = record.keyword_hash;
        // Impostor re-packs the publisher-signed record into its own
        // PROXY_STORE frame (sender_id = impostor ≠ publisher).
        let (_rid, frame) =
            impostor.build_proxy_store(key, record.data.clone(), record.signature);
        let on_buddy = buddy.handle_message(&frame, impostor_addr, impostor_noise, 2000);
        assert!(
            on_buddy.proxy_store_forward.is_none(),
            "must not amplify another publisher's record"
        );
    }

    #[test]
    fn proxy_store_rejects_non_firewalled_source() {
        let mut publisher = dht(82);
        let mut buddy = dht(83);
        let pub_noise = [0xAA; 32];
        let pub_addr = addr(82, 4672);

        // HighID source must not ride PROXY_STORE (would bypass anti-reflection).
        let contact = source_contact_at(82);
        let record =
            publisher.build_source_record([4u8; 16], [0u8; 32], 1, "direct.mkv", contact);
        let (_rid, frame) =
            publisher.build_proxy_store(record.keyword_hash, record.data.clone(), record.signature);
        let on_buddy = buddy.handle_message(&frame, pub_addr, pub_noise, 2000);
        assert!(on_buddy.proxy_store_forward.is_none());
        assert!(on_buddy.responses.is_empty());
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
        assert_eq!(
            b.contact_count(),
            0,
            "a forged frame must not seed the table"
        );
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
