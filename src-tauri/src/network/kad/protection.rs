use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// eMule PacketTracking.cpp: per-opcode limits within a 15-second window.
/// Global per-IP caps remain as a second layer of defense.
const OPCODE_WINDOW_SECS: u64 = 15;
const DEFAULT_OPCODE_LIMIT: u32 = 5;
/// Matches eMule's `SEC2MS(180)` outgoing-request expiry. We were using 30s,
/// which silently expired slow publish/search acks (KAD peers routinely take
/// several seconds to ack, and a full search cycle can sit in the `Lookup`
/// phase for >60s before the matching response arrives).
const TRACKER_EXPIRY_SECS: u64 = 180;
const MAX_OUTGOING_PER_IP_PER_SEC: u32 = 30;
/// Maximum `KADEMLIA2_SEARCH_RES` batches accepted for one outgoing
/// SearchKey/Source/Notes request. eMule may split results across multiple
/// packets, so one response per request is too strict; leaving the request as
/// an unlimited pass until the 180s expiry is too loose.
///
/// Sized to carry a whole `FETCH_PAGE_SIZE` page of results. A responder
/// fragments a page to fit `UDP_KAD_MAXFRAGMENT` (1420 bytes), so at the ~120
/// bytes a keyword entry with a typical filename occupies, a 200-entry page
/// needs roughly 18 datagrams. The previous 8 admitted only ~88 entries, so the
/// page-complete test that drives pagination could never fire for realistic
/// result sizes and every peer contributed only part of its first page.
const SEARCH_RES_BUDGET_PER_REQUEST: u32 = 20;

/// Per-IP global cap (second-level, matching eMule's "massive flood" detection).
const MAX_PACKETS_PER_SEC_UNKNOWN: u32 = 20;
const MAX_PACKETS_PER_SEC_KNOWN: u32 = 40;

/// The same caps, counted separately for Ember-native traffic.
///
/// Ember rides the shared KAD UDP socket, so both protocols arrive from the
/// same address and used to draw on one counter. A peer running both is the
/// normal case, and an ordinary KAD exchange with it — search results, publish
/// acks, packed responses — could then spend the allowance Ember needed to
/// finish a Noise handshake, so the DHT contact was never established. The
/// budget per protocol is unchanged; only the accounting is split, and a
/// spoofed flood still has to beat both windows.
const MAX_EMBER_PACKETS_PER_SEC_UNKNOWN: u32 = 20;
const MAX_EMBER_PACKETS_PER_SEC_KNOWN: u32 = 40;

/// Request opcodes whose responses are big enough to arrive packed. An
/// outstanding one of these in `outgoing_requests` marks the source as
/// answering us, which exempts it from the aggregate compressed budget in
/// `over_compressed_budget`.
const PACKED_RESPONSE_REQUESTS: [u8; 5] = [
    0x01, // BootstrapReq -> BootstrapRes (up to 20 contacts)
    0x21, // KadReq -> KadRes
    0x33, // SearchKeyReq -> SearchRes
    0x34, // SearchSourceReq -> SearchRes
    0x35, // SearchNotesReq -> SearchRes
];

const MAX_IP_ENTRIES: usize = 10_000;
const MAX_OPCODE_ENTRIES: usize = 50_000;

/// How many keys one eviction attempt inspects before giving up.
const EVICTION_PROBES: usize = 8;

/// Bounded-work eviction for the fixed-capacity counter tables.
///
/// Probes at most `EVICTION_PROBES` keys from the front of `order` and
/// removes the first one whose rate-limit window has already elapsed — such
/// an entry's counter resets to 1 on its very next packet anyway, so
/// reclaiming its slot loses no enforcement state. Entries still inside
/// their window are rotated to the back (CLOCK-style) and never evicted;
/// when nothing idle turns up the caller must drop the packet.
///
/// This replaces a `min_by_key(window_start)` full-map scan that had two
/// distinct problems. It was O(n) on the single `select!` arm that services
/// all inbound KAD UDP — with both tables full that is ~60,000 hash-map
/// iterations per packet from a fresh source IP, ahead of any real work,
/// and UDP source addresses are unauthenticated so filling them is cheap.
/// And because the sort key is the *window start* — refreshed only on
/// window rollover — the victim was systematically the entry that had been
/// accumulating the longest, i.e. the peer with the highest current count:
/// an attacker interleaving spoofed-source filler with its own traffic got
/// its own counter evicted and restarted at 1, defeating the per-opcode
/// limit entirely.
fn evict_idle<K, V>(
    map: &mut HashMap<K, V>,
    order: &mut VecDeque<K>,
    is_idle: impl Fn(&V) -> bool,
) -> bool
where
    K: Copy + Eq + std::hash::Hash,
{
    for _ in 0..EVICTION_PROBES {
        let Some(key) = order.pop_front() else {
            return false;
        };
        match map.get(&key) {
            Some(value) if is_idle(value) => {
                map.remove(&key);
                return true;
            }
            Some(_) => order.push_back(key),
            // Dropped by `cleanup()`, which rebuilds the order queues, so
            // this is only reachable transiently. Discard the stale key and
            // keep probing.
            None => {}
        }
    }
    false
}

/// Shared counters used when a per-key table is full and `evict_idle` found
/// nothing to reclaim.
///
/// Refusing every source that does not already hold a slot is a denial of
/// service we inflict on ourselves. These tables are filled purely by
/// *inbound* traffic and UDP source addresses are unauthenticated, so a few
/// thousand spoofed addresses sending one packet a second own every slot for
/// as long as they keep it up — and the layers in front of these tables carry
/// KAD, eD2K client UDP and Ember-native UDP alike, including the responses to
/// our own searches and publishes. Sharing a small fixed set of counters keeps
/// the work O(1) and still bounds a real flood: many sources spend one budget,
/// so a shard is exhausted faster than an individual counter, never slower.
const FALLBACK_SHARDS: usize = 64;

/// How many overflow sources one shard is sized to carry, applied as a
/// multiplier on the per-source limit that would otherwise have applied. Small
/// enough that a single source flooding through the fallback still hits a
/// ceiling within the same window it would have hit its own.
const FALLBACK_SOURCES_PER_SHARD: u32 = 4;

/// Shard for `ip`, FNV-1a over the address bytes. IPv4 is mapped into v6 so
/// both families run through the same fold.
fn fallback_shard(ip: IpAddr) -> usize {
    let octets = match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in octets {
        acc ^= u64::from(byte);
        acc = acc.wrapping_mul(0x0000_0100_0000_01B3);
    }
    (acc % FALLBACK_SHARDS as u64) as usize
}

/// Fixed-size shared windows; see [`FALLBACK_SHARDS`].
struct FallbackCounters {
    windows: [(u32, Instant); FALLBACK_SHARDS],
}

impl FallbackCounters {
    fn new() -> Self {
        FallbackCounters {
            windows: [(0, Instant::now()); FALLBACK_SHARDS],
        }
    }

    /// Charge one packet from `ip` to its shard and report whether the shard
    /// is now over `limit` for the current `window`.
    fn over_budget(&mut self, ip: IpAddr, now: Instant, window: Duration, limit: u32) -> bool {
        let slot = &mut self.windows[fallback_shard(ip)];
        if now.saturating_duration_since(slot.1) >= window {
            slot.0 = 1;
            slot.1 = now;
            false
        } else {
            slot.0 = slot.0.saturating_add(1);
            slot.0 > limit
        }
    }
}

fn opcode_limit(opcode: u8) -> u32 {
    match opcode {
        0x01 => 2,  // BootstrapReq
        0x11 => 3,  // HelloReq
        0x21 => 10, // KadReq (searches generate bursts)
        0x33 => 5,  // SearchKeyReq
        0x34 => 5,  // SearchSourceReq
        0x35 => 5,  // SearchNotesReq
        0x43 => 8,  // PublishKeyReq
        0x44 => 8,  // PublishSourceReq
        0x45 => 8,  // PublishNotesReq
        0x50 => 3,  // FirewalledReq
        0x51 => 5,  // FindBuddyReq — was falling through to the 5-request
        // default anyway, but named explicitly so this stays a
        // deliberate choice (buddy discovery can retry a few
        // times per search) rather than an accidental gap.
        0x52 => 3, // CallbackReq — keep below the per-session relay budget
        // so a single UDP source cannot burn the full buddy relay
        // allowance in one flood window. eMule still allows a few
        // retries per firewalled source.
        0x53 => 3, // Firewalled2Req
        0x60 => 3, // Ping
        _ => DEFAULT_OPCODE_LIMIT,
    }
}

/// Mirrors eMule's `InTrackListIsAllowedPacket` switch — only **request**
/// opcodes are flood-checked; responses fall through to `default: return 0`.
/// Using this gate on the incoming path was the missing piece that made
/// `PublishRes` (0x4B, or 0xFF for obfuscated-unknown) get rate-limited away
/// before ever reaching `decode_packet`, which is why `publish_confirmed`
/// stayed at 0 despite 100+ outstanding pending acks.
fn is_request_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        0x01 // KADEMLIA2_BOOTSTRAP_REQ
        | 0x08 // legacy BootstrapReq
        | 0x11 // KADEMLIA2_HELLO_REQ
        | 0x21 // KADEMLIA2_REQ
        | 0x33 // KADEMLIA2_SEARCH_KEY_REQ
        | 0x34 // KADEMLIA2_SEARCH_SOURCE_REQ
        | 0x35 // KADEMLIA2_SEARCH_NOTES_REQ
        | 0x43 // KADEMLIA2_PUBLISH_KEY_REQ
        | 0x44 // KADEMLIA2_PUBLISH_SOURCE_REQ
        | 0x45 // KADEMLIA2_PUBLISH_NOTES_REQ
        | 0x50 // KADEMLIA_FIREWALLED_REQ
        | 0x51 // KADEMLIA_FINDBUDDY_REQ
        | 0x52 // KADEMLIA_CALLBACK_REQ
        | 0x53 // KADEMLIA_FIREWALLED2_REQ
        | 0x60 // KADEMLIA2_PING
    )
}

pub struct FloodProtection {
    ip_counters: HashMap<IpAddr, (u32, Instant)>,
    /// Per-IP window for Ember-native UDP, kept apart from `ip_counters` so
    /// the two protocols sharing one socket cannot starve each other. See
    /// [`MAX_EMBER_PACKETS_PER_SEC_KNOWN`].
    ember_ip_counters: HashMap<IpAddr, (u32, Instant)>,
    /// Per-(IP, opcode) tracking within OPCODE_WINDOW_SECS
    opcode_counters: HashMap<(IpAddr, u8), (u32, Instant)>,
    /// Count of *outstanding* outgoing requests per (peer_ip, opcode).
    /// Previously a `HashSet`, which meant that if we sent e.g. five
    /// PublishSourceReqs to the same peer in a burst (common during a
    /// publish cycle that picks the same top-K closest peers for
    /// multiple files), only the first ack validated — every
    /// subsequent ack was rejected as "unsolicited" because the set
    /// entry was already consumed. With a counter we decrement per ack,
    /// so N requests can be matched by N acks in any order.
    ///
    /// Keyed by `IpAddr` (not `SocketAddr`) to match eMule's
    /// `AddTrackedOutPacket(uint32 dwIP, uint8 byOpcode)` — peers behind
    /// NAT sometimes reply from a different source port than we sent to,
    /// and eMule allows that.
    outgoing_requests: HashMap<(IpAddr, u8), u32>,
    /// Bounded SearchRes batches per outstanding Search* request. SearchRes is
    /// the one response type that is legitimately multi-packet per request.
    search_response_budgets: HashMap<(IpAddr, u8), u32>,
    request_times: HashMap<(IpAddr, u8), Instant>,
    outgoing_counters: HashMap<IpAddr, (u32, Instant)>,
    recent_ips: HashMap<IpAddr, Instant>,
    /// K21: per-IP compressed-packet counter within a 1-second window so
    /// we can decline to decompress over-quota traffic. Tracks
    /// (packet_count, compressed_wire_bytes, window_start).
    compressed_counters: HashMap<IpAddr, (u32, usize, Instant)>,
    /// K21: same budget applied across *all* sources. The per-IP window is
    /// charged once per source address, so a spoofed-source flood never
    /// trips it; this bounds aggregate decompression work regardless of how
    /// many addresses the traffic claims to come from.
    /// (packet_count, compressed_wire_bytes, window_start).
    global_compressed: (u32, usize, Instant),
    /// Probe order for the four fixed-capacity counter tables above. Kept
    /// alongside each map so a full table can be evicted from in O(1)
    /// instead of scanning every entry — see `evict_idle`.
    ip_order: VecDeque<IpAddr>,
    ember_ip_order: VecDeque<IpAddr>,
    opcode_order: VecDeque<(IpAddr, u8)>,
    outgoing_order: VecDeque<IpAddr>,
    compressed_order: VecDeque<IpAddr>,
    /// Degradation path for the two tables that have no aggregate counter of
    /// their own to fall back on — see [`FallbackCounters`]. The compressed
    /// table needs no shards: `global_compressed` is already its aggregate.
    ip_fallback: FallbackCounters,
    ember_ip_fallback: FallbackCounters,
    opcode_fallback: FallbackCounters,
}

/// Charge one packet to a per-IP one-second window and report whether the
/// source is now over `max_packets`.
///
/// Shared by the KAD and Ember windows so the two stay identical in behaviour
/// — including the saturated-table degradation, where a source we already have
/// a relationship with falls back to a shared shard rather than being refused
/// outright. Dropping those would discard the very responses we asked for.
fn over_per_ip_budget(
    counters: &mut HashMap<IpAddr, (u32, Instant)>,
    order: &mut VecDeque<IpAddr>,
    fallback: &mut FallbackCounters,
    ip: IpAddr,
    max_packets: u32,
    has_relationship: bool,
    now: Instant,
) -> bool {
    if !counters.contains_key(&ip) {
        if counters.len() >= MAX_IP_ENTRIES
            && !evict_idle(counters, order, |(_, t)| {
                now.saturating_duration_since(*t).as_secs() >= 1
            })
        {
            if !has_relationship {
                return true;
            }
            return fallback.over_budget(
                ip,
                now,
                Duration::from_secs(1),
                max_packets.saturating_mul(FALLBACK_SOURCES_PER_SHARD),
            );
        }
        order.push_back(ip);
    }
    let entry = counters.entry(ip).or_insert((0, now));
    if now.saturating_duration_since(entry.1).as_secs() >= 1 {
        entry.0 = 1;
        entry.1 = now;
        false
    } else {
        entry.0 += 1;
        entry.0 > max_packets
    }
}

impl FloodProtection {
    pub fn new() -> Self {
        FloodProtection {
            ip_counters: HashMap::new(),
            ember_ip_counters: HashMap::new(),
            opcode_counters: HashMap::new(),
            outgoing_requests: HashMap::new(),
            search_response_budgets: HashMap::new(),
            request_times: HashMap::new(),
            outgoing_counters: HashMap::new(),
            recent_ips: HashMap::new(),
            compressed_counters: HashMap::new(),
            global_compressed: (0, 0, Instant::now()),
            ip_order: VecDeque::new(),
            ember_ip_order: VecDeque::new(),
            opcode_order: VecDeque::new(),
            outgoing_order: VecDeque::new(),
            compressed_order: VecDeque::new(),
            ip_fallback: FallbackCounters::new(),
            ember_ip_fallback: FallbackCounters::new(),
            opcode_fallback: FallbackCounters::new(),
        }
    }

    /// Per-IP rate limit for Ember-native UDP, on its own window.
    ///
    /// There is no opcode layer: those limits are KAD-specific and a Noise
    /// frame is opaque until it is decrypted. The Ember DHT applies its own
    /// per-message budget after decryption.
    pub fn check_ember_rate_limit(&mut self, ip: IpAddr, known_peer: bool) -> bool {
        let now = Instant::now();
        let max_packets = if known_peer {
            MAX_EMBER_PACKETS_PER_SEC_KNOWN
        } else {
            MAX_EMBER_PACKETS_PER_SEC_UNKNOWN
        };
        let has_relationship = self.has_relationship(ip, known_peer);
        over_per_ip_budget(
            &mut self.ember_ip_counters,
            &mut self.ember_ip_order,
            &mut self.ember_ip_fallback,
            ip,
            max_packets,
            has_relationship,
            now,
        )
    }

    /// True when we have a prior relationship with `ip`: it is in our routing
    /// table, or we sent it a request inside `TRACKER_EXPIRY_SECS` and it may
    /// well be answering us. Used to decide who may degrade onto the shared
    /// fallback counters when a table is saturated — a spoofed source has
    /// neither property, so a flood cannot admit itself this way.
    fn has_relationship(&self, ip: IpAddr, known_peer: bool) -> bool {
        known_peer || self.has_recent_ip(ip)
    }

    /// K21: returns true when `ip` has exceeded its compressed-packet
    /// decompression budget for the current 1-second window. Callers
    /// should drop the packet (skip decompression) when this is true.
    pub fn over_compressed_budget(&mut self, ip: IpAddr, wire_bytes: usize) -> bool {
        const MAX_COMPRESSED_PER_SEC: u32 = 10;
        const MAX_COMPRESSED_BYTES_PER_SEC: usize = 64 * 1024;
        const MAX_COMPRESSED_ENTRIES: usize = 10_000;
        // Aggregate ceiling across every source: the per-IP window is charged
        // once per address, so a spoofed-source flood never trips it.
        //
        // Both halves have to stay live. At the old 200 packets the two caps
        // crossed at 5.2 KB — above the 1420-byte fragment ceiling — so the
        // byte budget could never bind and 200 packets was the whole control,
        // reachable by ~20 spoofed addresses at ~290 kbit/s, which then
        // blackholed every packed KAD packet (chiefly the inbound
        // `KADEMLIA2_SEARCH_RES` our own searches depend on) for the rest of
        // the second. 200/s is also below plausible honest load: unsolicited
        // packed traffic is mostly `PublishKeyReq` intake on a popular
        // storage node. At 1,000 the caps cross at ~1 KB, inside the range a
        // packed datagram actually occupies, so small packets are bounded by
        // the packet cap and large ones by the byte cap.
        const MAX_GLOBAL_COMPRESSED_PER_SEC: u32 = 1_000;
        const MAX_GLOBAL_COMPRESSED_BYTES_PER_SEC: usize = 1024 * 1024;
        let now = Instant::now();

        // A peer answering a request we actually sent must never be starved by
        // unsolicited traffic from elsewhere: the aggregate budget exists to
        // bound decompression work from strangers, not to drop the search
        // results we asked for. Probing the fixed set of request opcodes whose
        // replies can arrive packed keeps this O(1) on the packet path.
        //
        // Established before the per-IP table is consulted because table
        // pressure must not deny it either: the table holds one row per source
        // address and nothing authenticates those, so
        // `MAX_COMPRESSED_ENTRIES` spoofed addresses at a packet a second
        // otherwise blackhole every packed `KADEMLIA2_SEARCH_RES` we are
        // waiting on.
        let solicited = PACKED_RESPONSE_REQUESTS
            .iter()
            .any(|opcode| self.outgoing_requests.contains_key(&(ip, *opcode)));

        let has_slot = if self.compressed_counters.contains_key(&ip) {
            true
        } else if self.compressed_counters.len() < MAX_COMPRESSED_ENTRIES
            || evict_idle(
                &mut self.compressed_counters,
                &mut self.compressed_order,
                |(_, _, t)| now.saturating_duration_since(*t).as_secs() >= 1,
            )
        {
            self.compressed_order.push_back(ip);
            true
        } else {
            // No slot and nothing idle to reclaim. Skip the per-source layer
            // rather than denying: the aggregate counters below bound the
            // decompression work this control exists to bound, and they do it
            // without a per-source table for a flood to saturate.
            false
        };

        if has_slot {
            let entry = self.compressed_counters.entry(ip).or_insert((0, 0, now));
            if now.saturating_duration_since(entry.2).as_secs() >= 1 {
                entry.0 = 1;
                entry.1 = wire_bytes;
                entry.2 = now;
            } else {
                entry.0 = entry.0.saturating_add(1);
                entry.1 = entry.1.saturating_add(wire_bytes);
            }
            if entry.0 > MAX_COMPRESSED_PER_SEC || entry.1 > MAX_COMPRESSED_BYTES_PER_SEC {
                // Return before charging the aggregate counter. Charging it
                // first meant a source already over its own allowance still
                // spent budget it was never going to be permitted to use,
                // which is what let a handful of spoofed addresses buy a
                // global denial for free.
                return true;
            }
        }

        if now
            .saturating_duration_since(self.global_compressed.2)
            .as_secs()
            >= 1
        {
            self.global_compressed = (1, wire_bytes, now);
        } else {
            self.global_compressed.0 = self.global_compressed.0.saturating_add(1);
            self.global_compressed.1 = self.global_compressed.1.saturating_add(wire_bytes);
        }
        if self.global_compressed.0 <= MAX_GLOBAL_COMPRESSED_PER_SEC
            && self.global_compressed.1 <= MAX_GLOBAL_COMPRESSED_BYTES_PER_SEC
        {
            return false;
        }

        !solicited
    }

    /// Layer 1 only: per-(IP, opcode) request-flood check within
    /// `OPCODE_WINDOW_SECS`. Returns `true` if the packet should be
    /// dropped. Split out of `check_rate_limit_with_opcode` so
    /// `recheck_opcode_limit_post_decrypt` can apply it standalone without
    /// double-counting Layer 2 (the global per-IP cap), which the caller
    /// already charged once for this packet before decryption was even
    /// attempted.
    fn check_opcode_limit(&mut self, ip: IpAddr, known_peer: bool, opcode: u8) -> bool {
        if !is_request_opcode(opcode) {
            return false;
        }
        let now = Instant::now();
        let op_key = (ip, opcode);
        if !self.opcode_counters.contains_key(&op_key) {
            // K19: a full table must not reject every new peer outright —
            // one-shot spam would then lock legit peers out. Reclaim a slot
            // whose 15-second window has already lapsed instead. When every
            // probed slot is still live we never free space by evicting a
            // counter that is actively holding a peer under its limit: that
            // would hand the attacker a permanent bypass of the per-opcode
            // cap, since `OPCODE_WINDOW_SECS` bounds how long any one entry
            // stays live, not how long the table stays saturated — an
            // attacker refreshing it at ~3,333 packets/sec holds it open
            // indefinitely.
            if self.opcode_counters.len() >= MAX_OPCODE_ENTRIES
                && !evict_idle(
                    &mut self.opcode_counters,
                    &mut self.opcode_order,
                    |(_, t)| now.saturating_duration_since(*t).as_secs() >= OPCODE_WINDOW_SECS,
                )
            {
                // Nothing idle to reclaim, and evicting a live counter is off
                // the table for the reason above. A stranger is still refused
                // — that is what stops a flood buying itself admission — but
                // refusing *everyone* hands the attacker the whole table as a
                // lockout, so a peer we already deal with degrades onto a
                // shared counter instead of being dropped outright.
                if !self.has_relationship(ip, known_peer) {
                    return true;
                }
                let limit = opcode_limit(opcode);
                let effective = if known_peer { limit * 2 } else { limit };
                return self.opcode_fallback.over_budget(
                    ip,
                    now,
                    Duration::from_secs(OPCODE_WINDOW_SECS),
                    effective.saturating_mul(FALLBACK_SOURCES_PER_SHARD),
                );
            }
            self.opcode_order.push_back(op_key);
        }
        let op_entry = self.opcode_counters.entry(op_key).or_insert((0, now));
        if now.saturating_duration_since(op_entry.1).as_secs() >= OPCODE_WINDOW_SECS {
            op_entry.0 = 1;
            op_entry.1 = now;
            false
        } else {
            op_entry.0 += 1;
            let limit = opcode_limit(opcode);
            let effective = if known_peer { limit * 2 } else { limit };
            op_entry.0 > effective
        }
    }

    /// Re-applies the Layer 1 per-opcode request-flood check for an
    /// obfuscated packet now that decryption + `decode_packet` have
    /// revealed its real opcode. `check_rate_limit_with_opcode` necessarily
    /// skips Layer 1 for every obfuscated packet (opcode is unknown as
    /// `0xFF` pre-decrypt); without this follow-up call, obfuscated
    /// requests would only ever face the much looser Layer 2 global-per-IP
    /// cap (20-40 packets/sec) instead of the tight per-opcode limits
    /// (e.g. `SearchKeyReq`'s 5-per-15s), which exist specifically to bound
    /// `SearchRes` UDP reflection/amplification. Only call this for
    /// obfuscated packets — plain packets already got the accurate opcode
    /// on the pre-decrypt call, so re-running this for them would
    /// double-count Layer 1 too.
    ///
    /// `real_opcode` should come from `messages::request_wire_opcode`,
    /// which returns `None` for non-request messages (responses/acks) —
    /// those never reach this call in the first place.
    pub fn recheck_opcode_limit_post_decrypt(
        &mut self,
        ip: IpAddr,
        known_peer: bool,
        real_opcode: u8,
    ) -> bool {
        self.check_opcode_limit(ip, known_peer, real_opcode)
    }

    /// Rate-limit with opcode awareness matching eMule PacketTracking.cpp.
    ///
    /// `opcode` is the byte at `data[1]` for a plain 0xE4/0xE5 packet or
    /// `0xFF` when we can't peek inside (obfuscated envelope). It is *not*
    /// trustworthy for classifying responses — an obfuscated PublishRes
    /// looks identical to any other obfuscated packet until we decrypt it.
    pub fn check_rate_limit_with_opcode(
        &mut self,
        ip: IpAddr,
        known_peer: bool,
        opcode: u8,
    ) -> bool {
        // Layer 1: per-(IP, opcode) within OPCODE_WINDOW_SECS.
        //
        // Matches eMule `InTrackListIsAllowedPacket`'s `default: return 0;`
        // branch: responses bypass the flood check entirely. Applying it to
        // responses was dropping PublishRes/KadRes/SearchRes packets before
        // `decode_packet` could tell them apart, which manifested as
        // `publish_confirmed` stuck at 0 with `wire=0` in diagnostics.
        //
        // Obfuscated packets (opcode == 0xFF) also bypass Layer 1 here
        // because we can't tell a request from a response until after
        // decryption — `is_request_opcode(0xFF)` is false, so
        // `check_opcode_limit` naturally no-ops for them. See
        // `recheck_opcode_limit_post_decrypt`, which the caller re-runs
        // once the real opcode is known, so this isn't a permanent bypass,
        // just a deferral.
        if self.check_opcode_limit(ip, known_peer, opcode) {
            return true;
        }

        let now = Instant::now();
        let max_packets = if known_peer {
            MAX_PACKETS_PER_SEC_KNOWN
        } else {
            MAX_PACKETS_PER_SEC_UNKNOWN
        };

        // Layer 2: global per-IP per-second cap.
        //
        // Unlike Layer 1 this gate sees *responses* too, so denying every
        // source without a slot drops the SearchRes and PublishRes answering
        // our own requests — keyword search then silently returns nothing
        // while a spoofed flood holds the table. Sources we have a
        // relationship with degrade onto a shared counter; strangers are
        // still refused. `over_per_ip_budget` owns that rule.
        let has_relationship = self.has_relationship(ip, known_peer);
        over_per_ip_budget(
            &mut self.ip_counters,
            &mut self.ip_order,
            &mut self.ip_fallback,
            ip,
            max_packets,
            has_relationship,
            now,
        )
    }

    /// Returns true if a packet from port 53 should be dropped (unencrypted).
    pub fn is_dns_port(addr: &SocketAddr) -> bool {
        addr.port() == 53
    }

    /// Check if we should throttle an outgoing packet to this IP.
    /// Returns true if we've sent too many packets to this IP recently.
    pub fn check_outgoing_rate(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if !self.outgoing_counters.contains_key(&ip) {
            // K19: reclaim a lapsed one-second window instead of
            // hard-failing, and throttle rather than evict a live counter.
            if self.outgoing_counters.len() >= MAX_IP_ENTRIES
                && !evict_idle(
                    &mut self.outgoing_counters,
                    &mut self.outgoing_order,
                    |(_, t)| now.saturating_duration_since(*t).as_secs() >= 1,
                )
            {
                return true;
            }
            self.outgoing_order.push_back(ip);
        }
        let entry = self.outgoing_counters.entry(ip).or_insert((0, now));

        if now.saturating_duration_since(entry.1).as_secs() >= 1 {
            entry.0 = 1;
            entry.1 = now;
            false
        } else {
            entry.0 += 1;
            entry.0 > MAX_OUTGOING_PER_IP_PER_SEC
        }
    }

    /// Record an outgoing request so we can validate incoming responses.
    /// Counter-based: sending N requests to the same (ip, opcode) leaves
    /// N entries to be matched by N replies. Any ordering is acceptable.
    ///
    /// Keyed by IP only — not (IP, port) — to match eMule
    /// `AddTrackedOutPacket(dwIP, byOpcode)`. Some NATs rewrite the source
    /// port on reply, so an SocketAddr-keyed table silently dropped those
    /// acks.
    pub fn track_request(&mut self, addr: SocketAddr, opcode: u8) {
        let now = Instant::now();
        let key = (addr.ip(), opcode);
        let count = self.outgoing_requests.entry(key).or_insert(0);
        *count = count.saturating_add(1);
        if matches!(opcode, 0x33 | 0x34 | 0x35) {
            let budget = self.search_response_budgets.entry(key).or_insert(0);
            *budget = budget.saturating_add(SEARCH_RES_BUDGET_PER_REQUEST);
        }
        // `request_times` is dual-purpose:
        //   1. `cleanup()` expires (ip, opcode) entries whose most
        //      recent send is older than `TRACKER_EXPIRY_SECS` — this
        //      requires the **latest** timestamp, otherwise a
        //      continuously-active key would be expired out from
        //      under live requests.
        //   2. The `validate_response` ambiguous-PublishRes path picks
        //      the earliest (ip, opcode) among {0x43, 0x44, 0x45} —
        //      this would prefer the **oldest** timestamp.
        //
        // These two requirements are in tension with a single field.
        // We favour correctness of (1) (never drop a live key) over
        // precision of (2) (whose comment already admits it's a
        // best-effort heuristic — the authoritative confirmation
        // count is kept at the higher layer by `publish_pending`).
        // The relative ordering within a burst still holds roughly
        // because three concurrent publishes almost always get their
        // first `track_request` in quick succession, and each
        // subsequent send bumps all three keys' timestamps by
        // similar amounts.
        self.request_times.insert(key, now);
        self.recent_ips.insert(addr.ip(), now);
    }

    /// Helper: decrement the counter for `key` and return whether an
    /// entry was consumed. The entry is removed entirely (along with
    /// `request_times`) when the count reaches zero.
    fn consume_outgoing(&mut self, key: &(IpAddr, u8)) -> bool {
        if let Some(count) = self.outgoing_requests.get_mut(key) {
            if *count > 0 {
                *count -= 1;
                if *count == 0 {
                    self.outgoing_requests.remove(key);
                    self.search_response_budgets.remove(key);
                    self.request_times.remove(key);
                }
                return true;
            }
        }
        false
    }

    /// Check if we have a matching outgoing request for this response.
    /// Returns true if valid (we sent a request), false if unsolicited.
    pub fn validate_response(&mut self, addr: SocketAddr, response_opcode: u8) -> bool {
        let ip = addr.ip();
        let request_opcode = match response_opcode {
            0x09 => Some(0x01u8), // BootstrapRes -> BootstrapReq
            0x19 => Some(0x11),   // HelloRes -> HelloReq
            0x22 => Some(0x19),   // HelloResAck -> HelloRes
            0x29 => Some(0x21),   // KadRes -> KadReq
            0x3B => Some(0x33),   // SearchRes -> SearchKeyReq (or 0x34, 0x35)
            0x4B => Some(0x43),   // PublishRes -> PublishKeyReq (or 0x44, 0x45)
            0x4C => Some(0x4B),   // PublishResAck -> PublishRes
            0x5A => Some(0x51),   // FindBuddyRes -> FindBuddyReq
            0x61 => Some(0x60),   // Pong -> Ping
            0x58 => Some(0x50),   // FirewalledRes -> FirewalledReq or Firewalled2Req
            _ => None,
        };

        if let Some(req_op) = request_opcode {
            if response_opcode == 0x3B {
                // KAD peers send multiple SearchRes packets per Search*Req
                // (result batches). Consume a bounded per-request budget so
                // legitimate multi-packet replies still pass while unsolicited
                // floods do not get a 180-second unlimited window.
                for cand in [req_op, 0x34, 0x35] {
                    let key = (ip, cand);
                    if let Some(budget) = self.search_response_budgets.get_mut(&key) {
                        if *budget > 0 {
                            *budget -= 1;
                            if *budget == 0 {
                                self.search_response_budgets.remove(&key);
                                self.outgoing_requests.remove(&key);
                                self.request_times.remove(&key);
                            }
                            return true;
                        }
                    }
                }
                return false;
            }
            // PublishRes (0x4B) is ambiguous: it could ack any of
            // {0x43 PublishKeyReq, 0x44 PublishSourceReq, 0x45
            // PublishNotesReq}. The protection layer can't see the
            // target hash inside the response payload, so it can't
            // know which specific publish is being acked. To avoid
            // systematically biasing 0x43 (which leaves the other
            // counters elevated until expiry), consume the *oldest*
            // pending publish across the three — peers typically
            // respond in roughly send order. The actual confirmation
            // count is tracked at the higher layer via
            // `publish_pending` keyed by `(target_hash, addr)`, which
            // is the source of truth for user-visible counts.
            if response_opcode == 0x4B {
                let mut oldest_op: Option<u8> = None;
                let mut oldest_t: Option<Instant> = None;
                for cand in [req_op, 0x44, 0x45] {
                    if let Some(&t) = self.request_times.get(&(ip, cand)) {
                        if oldest_t.is_none_or(|ot| t < ot) {
                            oldest_t = Some(t);
                            oldest_op = Some(cand);
                        }
                    }
                }
                if let Some(op) = oldest_op {
                    if self.consume_outgoing(&(ip, op)) {
                        return true;
                    }
                }
            } else if self.consume_outgoing(&(ip, req_op)) {
                return true;
            }
            // For FirewalledRes, also check Firewalled2Req (0x53)
            if response_opcode == 0x58 && self.consume_outgoing(&(ip, 0x53)) {
                return true;
            }
        }
        false
    }

    /// O(1) check if we've communicated with this IP recently.
    pub fn has_recent_ip(&self, ip: IpAddr) -> bool {
        if let Some(last) = self.recent_ips.get(&ip) {
            Instant::now().saturating_duration_since(*last).as_secs() < TRACKER_EXPIRY_SECS
        } else {
            false
        }
    }

    /// Clean up stale tracking entries.
    pub fn cleanup(&mut self) {
        let now = Instant::now();

        self.ip_counters
            .retain(|_, (_, last)| now.saturating_duration_since(*last).as_secs() < 60);

        self.ember_ip_counters
            .retain(|_, (_, last)| now.saturating_duration_since(*last).as_secs() < 60);

        self.opcode_counters.retain(|_, (_, last)| {
            now.saturating_duration_since(*last).as_secs() < OPCODE_WINDOW_SECS * 2
        });

        self.outgoing_counters
            .retain(|_, (_, last)| now.saturating_duration_since(*last).as_secs() < 60);

        let stale: Vec<(IpAddr, u8)> = self
            .request_times
            .iter()
            .filter(|(_, time)| {
                now.saturating_duration_since(**time).as_secs() > TRACKER_EXPIRY_SECS
            })
            .map(|(key, _)| *key)
            .collect();
        for key in stale {
            self.outgoing_requests.remove(&key);
            self.search_response_budgets.remove(&key);
            self.request_times.remove(&key);
        }

        self.recent_ips
            .retain(|_, last| now.saturating_duration_since(*last).as_secs() < TRACKER_EXPIRY_SECS);
        // K21: compressed-packet budget table follows the same 60s cleanup.
        self.compressed_counters
            .retain(|_, (_, _, last)| now.saturating_duration_since(*last).as_secs() < 60);

        // Drop the order-queue records for everything just retained away,
        // so `evict_idle` never wastes probes on keys that no longer exist.
        let ip_counters = &self.ip_counters;
        self.ip_order.retain(|ip| ip_counters.contains_key(ip));
        let ember_ip_counters = &self.ember_ip_counters;
        self.ember_ip_order
            .retain(|ip| ember_ip_counters.contains_key(ip));
        let opcode_counters = &self.opcode_counters;
        self.opcode_order
            .retain(|key| opcode_counters.contains_key(key));
        let outgoing_counters = &self.outgoing_counters;
        self.outgoing_order
            .retain(|ip| outgoing_counters.contains_key(ip));
        let compressed_counters = &self.compressed_counters;
        self.compressed_order
            .retain(|ip| compressed_counters.contains_key(ip));
    }

    /// Test-only: rewind every rate-limit window start by `by`, so eviction
    /// behaviour against idle vs. live counters can be exercised without
    /// sleeping through a 15-second opcode window.
    #[cfg(test)]
    fn age_counters(&mut self, by: std::time::Duration) {
        fn rewind(at: &mut Instant, by: std::time::Duration) {
            if let Some(earlier) = at.checked_sub(by) {
                *at = earlier;
            }
        }
        for (_, at) in self.ip_counters.values_mut() {
            rewind(at, by);
        }
        for (_, at) in self.ember_ip_counters.values_mut() {
            rewind(at, by);
        }
        for (_, at) in self.opcode_counters.values_mut() {
            rewind(at, by);
        }
        for (_, at) in self.outgoing_counters.values_mut() {
            rewind(at, by);
        }
        for (_, _, at) in self.compressed_counters.values_mut() {
            rewind(at, by);
        }
    }
}

#[cfg(test)]
mod kad_protection_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn filler_ip(i: usize) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(
            ((i >> 24) & 0xFF) as u8,
            ((i >> 16) & 0xFF) as u8,
            ((i >> 8) & 0xFF) as u8,
            (i & 0xFF) as u8,
        ))
    }

    /// K19: once every window in a full opcode table has lapsed, those
    /// counters would reset on their next packet anyway, so their slots are
    /// free for the taking and a fresh peer must not be locked out.
    #[test]
    fn full_opcode_table_reclaims_idle_slots() {
        let mut fp = FloodProtection::new();
        for i in 0..MAX_OPCODE_ENTRIES {
            let _ = fp.check_rate_limit_with_opcode(filler_ip(i), false, 0x21);
        }
        assert_eq!(fp.opcode_counters.len(), MAX_OPCODE_ENTRIES);

        fp.age_counters(Duration::from_secs(OPCODE_WINDOW_SECS + 1));
        let new_ip = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 254));
        assert!(
            !fp.check_rate_limit_with_opcode(new_ip, false, 0x21),
            "an elapsed window is a free slot; a fresh peer must be admitted"
        );
        assert_eq!(
            fp.opcode_counters.len(),
            MAX_OPCODE_ENTRIES,
            "admitting the new peer must reclaim a slot, not grow the table"
        );
    }

    /// The eviction victim used to be `min_by_key(window_start)`, and the
    /// window start is only refreshed on rollover — so the entry picked was
    /// always the one that had been accumulating longest, i.e. the peer with
    /// the *highest* count. An attacker interleaving its own requests with
    /// spoofed-source filler therefore got its own counter evicted and
    /// restarted at 1. A full table must now drop the incoming packet
    /// instead of freeing a slot at a live counter's expense.
    #[test]
    fn full_opcode_table_never_evicts_a_live_counter() {
        let mut fp = FloodProtection::new();
        let victim = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        // KadReq (0x21) allows 10 per window for an unknown peer.
        for i in 0..10 {
            assert!(
                !fp.check_opcode_limit(victim, false, 0x21),
                "KadReq #{} is still inside the per-opcode budget",
                i + 1
            );
        }
        // Spoofed-source filler, inserted after the victim so the victim is
        // the oldest entry and hence the old code's eviction target.
        for i in 0..(MAX_OPCODE_ENTRIES - 1) {
            let _ = fp.check_opcode_limit(filler_ip(i), false, 0x21);
        }
        assert_eq!(fp.opcode_counters.len(), MAX_OPCODE_ENTRIES);

        let fresh = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 254));
        assert!(
            fp.check_opcode_limit(fresh, false, 0x21),
            "with no idle slot the packet must be dropped, not admitted by \
             evicting somebody's live counter"
        );
        assert!(
            fp.check_opcode_limit(victim, false, 0x21),
            "the victim's 11th KadReq must still be refused — its counter \
             must survive a table-full admission attempt"
        );
    }

    /// The flip side of the test above. Refusing every source that has no
    /// slot is a lockout an attacker can hold open indefinitely, and these
    /// tables are filled purely by inbound traffic from unauthenticated UDP
    /// source addresses. A peer we already deal with must keep getting
    /// through; a stranger must not.
    #[test]
    fn full_opcode_table_degrades_instead_of_locking_everyone_out() {
        let mut fp = FloodProtection::new();
        for i in 0..MAX_OPCODE_ENTRIES {
            let _ = fp.check_opcode_limit(filler_ip(i), false, 0x21);
        }
        assert_eq!(fp.opcode_counters.len(), MAX_OPCODE_ENTRIES);

        let known = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        assert!(
            !fp.check_opcode_limit(known, true, 0x21),
            "a routing-table peer must not be locked out by a saturated table"
        );
        assert!(
            fp.check_opcode_limit(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), false, 0x21),
            "a stranger is still refused, so the fallback cannot be used to \
             bypass a full table"
        );
        assert_eq!(
            fp.opcode_counters.len(),
            MAX_OPCODE_ENTRIES,
            "the fallback shares counters; it must not grow the table"
        );
    }

    /// Layer 2 sees responses as well as requests, so a full `ip_counters`
    /// table used to blackhole the `SearchRes`/`PublishRes` answering our own
    /// requests — keyword search then returns nothing at all. Roughly
    /// `MAX_IP_ENTRIES` spoofed addresses at a packet a second is enough to
    /// hold every slot.
    #[test]
    fn full_ip_table_still_admits_a_peer_we_queried() {
        let mut fp = FloodProtection::new();
        let peer: SocketAddr = "198.51.100.10:4672".parse().unwrap();
        fp.track_request(peer, 0x33);

        // 0x4B (PublishRes) is not a request opcode, so this exercises Layer 2
        // alone.
        for i in 0..MAX_IP_ENTRIES {
            let _ = fp.check_rate_limit_with_opcode(filler_ip(i), false, 0x4B);
        }
        assert_eq!(fp.ip_counters.len(), MAX_IP_ENTRIES);

        assert!(
            fp.check_rate_limit_with_opcode(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200)), false, 0x4B),
            "a stranger arriving at a saturated table is still refused"
        );
        assert!(
            !fp.check_rate_limit_with_opcode(peer.ip(), false, 0x4B),
            "the response from a peer we queried must survive a table held \
             open by spoofed sources"
        );
    }

    /// The fallback is shared, so it still bounds a flood: one source that
    /// degrades onto a shard cannot send without limit just because the table
    /// was full when it arrived.
    #[test]
    fn fallback_counter_still_limits_a_flooding_source() {
        let mut fp = FloodProtection::new();
        let peer: SocketAddr = "198.51.100.11:4672".parse().unwrap();
        fp.track_request(peer, 0x33);
        for i in 0..MAX_IP_ENTRIES {
            let _ = fp.check_rate_limit_with_opcode(filler_ip(i), false, 0x4B);
        }

        let budget = MAX_PACKETS_PER_SEC_UNKNOWN * FALLBACK_SOURCES_PER_SHARD;
        for i in 0..budget {
            assert!(
                !fp.check_rate_limit_with_opcode(peer.ip(), false, 0x4B),
                "packet {} is inside the shared fallback budget",
                i + 1
            );
        }
        assert!(
            fp.check_rate_limit_with_opcode(peer.ip(), false, 0x4B),
            "the shared fallback must still cut off a flood"
        );
    }

    /// Regression guard for the obfuscation amplification bypass: the
    /// pre-decrypt call always sees opcode 0xFF and so must never trip
    /// Layer 1, but once the real opcode is known post-decrypt,
    /// `recheck_opcode_limit_post_decrypt` must enforce the *same*
    /// per-opcode limit a plaintext packet of that type would have hit —
    /// otherwise obfuscated SearchKeyReq floods only face the much looser
    /// Layer 2 global cap, giving an attacker an amplification-friendly
    /// bypass of the SearchRes-bounding limit.
    #[test]
    fn obfuscated_packet_gets_opcode_limit_enforced_post_decrypt() {
        let mut fp = FloodProtection::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20));

        // Pre-decrypt call with the 0xFF hint must never rate-limit on
        // opcode grounds alone (Layer 1 is a no-op for 0xFF). Stay well
        // under Layer 2's global per-IP cap so this only exercises Layer 1.
        for _ in 0..5 {
            assert!(
                !fp.check_rate_limit_with_opcode(ip, false, 0xFF),
                "pre-decrypt obfuscated hint (0xFF) must not trip Layer 1"
            );
        }

        // A fresh IP's post-decrypt SearchKeyReq (0x33) opcode limit is 5
        // per OPCODE_WINDOW_SECS for an unknown peer — the same limit a
        // plaintext SearchKeyReq flood would face.
        for i in 0..5 {
            assert!(
                !fp.recheck_opcode_limit_post_decrypt(ip, false, 0x33),
                "SearchKeyReq #{} should still be within the per-opcode budget",
                i + 1
            );
        }
        assert!(
            fp.recheck_opcode_limit_post_decrypt(ip, false, 0x33),
            "6th obfuscated SearchKeyReq within the window must be rate-limited, \
             matching the plaintext per-opcode cap instead of only the looser \
             Layer 2 global cap"
        );
    }

    /// K21: 11th compressed packet from same IP in 1s should be declined.
    /// Ember rides the KAD socket, so both protocols arrive from one address.
    /// While they shared a counter, an ordinary KAD exchange with a dual-stack
    /// peer could spend the allowance Ember needed to finish its Noise
    /// handshake with that same peer, and the DHT contact never formed.
    #[test]
    fn kad_traffic_does_not_spend_the_ember_budget() {
        let mut fp = FloodProtection::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 30));

        for i in 0..MAX_PACKETS_PER_SEC_UNKNOWN {
            assert!(
                !fp.check_rate_limit_with_opcode(ip, false, 0xFF),
                "KAD packet {} is inside its own budget",
                i + 1
            );
        }
        assert!(
            fp.check_rate_limit_with_opcode(ip, false, 0xFF),
            "the KAD window is spent"
        );

        assert!(
            !fp.check_ember_rate_limit(ip, false),
            "Ember must still be able to hand shake with the same peer"
        );
    }

    /// Splitting the counters must not hand out a free pass: the Ember window
    /// enforces its own cap, and spending it leaves KAD unaffected.
    #[test]
    fn the_ember_budget_caps_a_flood_without_touching_kad() {
        let mut fp = FloodProtection::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 31));

        for i in 0..MAX_EMBER_PACKETS_PER_SEC_UNKNOWN {
            assert!(
                !fp.check_ember_rate_limit(ip, false),
                "Ember packet {} is inside the budget",
                i + 1
            );
        }
        assert!(
            fp.check_ember_rate_limit(ip, false),
            "an Ember flood is still capped"
        );
        assert!(
            !fp.check_rate_limit_with_opcode(ip, false, 0xFF),
            "and KAD is independent in the other direction too"
        );
    }

    #[test]
    fn compressed_budget_enforced() {
        let mut fp = FloodProtection::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        for _ in 0..10 {
            assert!(!fp.over_compressed_budget(ip, 1400));
        }
        assert!(
            fp.over_compressed_budget(ip, 1400),
            "11th compressed packet must trip the budget"
        );
    }

    #[test]
    fn compressed_byte_budget_is_independent_of_packet_count() {
        let mut fp = FloodProtection::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        assert!(!fp.over_compressed_budget(ip, 32 * 1024));
        assert!(fp.over_compressed_budget(ip, 32 * 1024 + 1));
    }

    /// K21: the per-IP window is charged once per source address, so a
    /// spoofed-source flood never trips it. The aggregate budget must.
    #[test]
    fn global_compressed_budget_bounds_spoofed_sources() {
        let mut fp = FloodProtection::new();
        for i in 0..16 {
            assert!(
                !fp.over_compressed_budget(filler_ip(i), 64 * 1024),
                "packet {i} from a distinct source is within both budgets"
            );
        }
        assert!(
            fp.over_compressed_budget(filler_ip(16), 64 * 1024),
            "a fresh source address must not buy more aggregate \
             decompression once the global byte budget is spent"
        );
    }

    /// The aggregate counter used to be charged before (and independently of)
    /// the per-IP decision, so packets we were already refusing still spent
    /// global budget. ~20 spoofed addresses at 20 packets each then blackholed
    /// every packed KAD packet for the rest of the second.
    #[test]
    fn packets_the_per_ip_budget_refuses_do_not_spend_global_budget() {
        let mut fp = FloodProtection::new();
        // 60 addresses x 20 packets is 1,200 charges if every packet counts
        // against the aggregate, but only 600 once each address's 10-packet
        // per-IP allowance stops paying — either side of the packet cap.
        for i in 0..60 {
            for _ in 0..20 {
                fp.over_compressed_budget(filler_ip(i), 400);
            }
        }
        assert!(
            !fp.over_compressed_budget(filler_ip(1000), 400),
            "a flood that is already being refused per-IP must not deny \
             service to everyone else"
        );
    }

    /// A peer answering a request we sent must not be starved by unsolicited
    /// compressed traffic — losing `KADEMLIA2_SEARCH_RES` this way stops
    /// keyword search returning results at all.
    #[test]
    fn solicited_sources_survive_an_exhausted_global_budget() {
        let mut fp = FloodProtection::new();
        let peer: SocketAddr = "203.0.113.20:4672".parse().unwrap();
        fp.track_request(peer, 0x33);

        // Spend the whole aggregate byte budget from other sources, staying
        // inside each one's per-IP allowance so it is genuinely charged.
        for i in 0..17 {
            fp.over_compressed_budget(filler_ip(i), 64 * 1024);
        }
        assert!(
            fp.over_compressed_budget(filler_ip(100), 1400),
            "an unsolicited source must be refused once the aggregate budget is spent"
        );
        assert!(
            !fp.over_compressed_budget(peer.ip(), 1400),
            "a SearchRes from a peer we queried must still be decoded"
        );
    }

    /// outgoing_requests is multiset: sending N requests to the same
    /// (addr, opcode) pair must validate N replies in any order, not
    /// just the first. This was the root cause of `publish_confirmed`
    /// being stuck at 0 — the old `HashSet` collapsed duplicates so only
    /// the first ack per peer ever validated.
    #[test]
    fn outgoing_requests_multiset_counts_each_ack() {
        let mut fp = FloodProtection::new();
        let addr: SocketAddr = "203.0.113.9:4672".parse().unwrap();
        // Track five PublishSourceReq sends to the same peer.
        for _ in 0..5 {
            fp.track_request(addr, 0x44);
        }
        // Each incoming PublishRes should validate against one of
        // those entries until all are consumed.
        for i in 0..5 {
            assert!(
                fp.validate_response(addr, 0x4B),
                "PublishRes #{} must match a tracked request",
                i + 1
            );
        }
        // The sixth PublishRes has no backing request and must be
        // rejected as unsolicited.
        assert!(
            !fp.validate_response(addr, 0x4B),
            "6th PublishRes must be rejected once all 5 tracked requests are consumed"
        );
    }

    /// eMule matches acks by IP only (`AddTrackedOutPacket(dwIP, …)`).
    /// A peer behind NAT may reply from a different source port than we
    /// sent to; the old SocketAddr-keyed table dropped those acks as
    /// unsolicited, which was a second cause of `publish_confirmed=0`.
    #[test]
    fn validate_response_matches_across_source_ports() {
        let mut fp = FloodProtection::new();
        let sent_to: SocketAddr = "203.0.113.9:4672".parse().unwrap();
        let reply_from: SocketAddr = "203.0.113.9:54321".parse().unwrap();
        fp.track_request(sent_to, 0x44);
        assert!(
            fp.validate_response(reply_from, 0x4B),
            "reply from a different source port on the same IP must still validate"
        );
    }

    /// SearchRes is legitimately multi-packet per one Search* request, but the
    /// tracker must not leave an unlimited 180-second response window open.
    #[test]
    fn search_response_budget_allows_batches_but_caps_floods() {
        let mut fp = FloodProtection::new();
        let addr: SocketAddr = "203.0.113.11:4672".parse().unwrap();
        fp.track_request(addr, 0x34);

        for i in 0..SEARCH_RES_BUDGET_PER_REQUEST {
            assert!(
                fp.validate_response(addr, 0x3B),
                "SearchRes batch {} should consume the request budget",
                i + 1
            );
        }
        assert!(
            !fp.validate_response(addr, 0x3B),
            "SearchRes beyond the per-request budget must be rejected"
        );
    }

    /// Regression test for the `publish_confirmed=0, wire=0` symptom: an
    /// obfuscated PublishRes presents as `opcode_hint=0xFF` before
    /// decryption, and eMule's `InTrackListIsAllowedPacket` falls through
    /// to `default: return 0;` for anything that isn't a tracked request
    /// opcode. So responses — encrypted or not — must never be
    /// rate-limited by the opcode layer.
    #[test]
    fn responses_bypass_per_opcode_rate_limit() {
        let mut fp = FloodProtection::new();
        let res_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        // Plain PublishRes (0x4B): 15 in a row from a known peer must
        // all pass the opcode layer. Under the old rules we'd stop at
        // DEFAULT_OPCODE_LIMIT*2 = 10 per 15s. Cap at 15 so Layer 2's
        // 40-pkt/s known-peer ceiling doesn't confuse the signal.
        for i in 0..15 {
            assert!(
                !fp.check_rate_limit_with_opcode(res_ip, true, 0x4B),
                "PublishRes #{} must not be rate-limited by opcode layer",
                i + 1
            );
        }
        // Obfuscated envelope: opcode_hint=0xFF. Must also fall through
        // the opcode layer because we can't classify it pre-decryption.
        let obf_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 43));
        for _ in 0..15 {
            assert!(!fp.check_rate_limit_with_opcode(obf_ip, true, 0xFF));
        }
        // Requests still get rate-limited. Bootstrap req limit is 2 per
        // 15s for unknown peers, so packet #3 must trip.
        let req_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 44));
        assert!(!fp.check_rate_limit_with_opcode(req_ip, false, 0x01));
        assert!(!fp.check_rate_limit_with_opcode(req_ip, false, 0x01));
        assert!(
            fp.check_rate_limit_with_opcode(req_ip, false, 0x01),
            "3rd BootstrapReq from unknown peer must be rate-limited"
        );
    }
}
