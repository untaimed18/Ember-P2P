//! KAD wire helpers: sending packets and responses, firewall checks and
//! probes, external IP tracking, and bootstrap contact limits.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

pub(super) const FIREWALL_REQ_COOLDOWN_SECS: i64 = 60;
pub(super) const MAX_FIREWALL_REQ_COOLDOWN_ENTRIES: usize = 4096;

pub(super) struct TokenBucket {
    pub(super) tokens: f64,
    pub(super) capacity: f64,
    pub(super) refill_per_second: f64,
    pub(super) last_refill: std::time::Instant,
}

impl TokenBucket {
    pub(super) fn new(capacity: usize, refill_per_second: f64) -> Self {
        Self {
            tokens: capacity as f64,
            capacity: capacity as f64,
            refill_per_second,
            last_refill: std::time::Instant::now(),
        }
    }

    pub(super) fn try_take(&mut self) -> bool {
        let now = std::time::Instant::now();
        self.tokens = (self.tokens
            + now
                .saturating_duration_since(self.last_refill)
                .as_secs_f64()
                * self.refill_per_second)
            .min(self.capacity);
        self.last_refill = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }

    /// Peek whether the bucket is under stress without consuming a token.
    pub(super) fn available_tokens(&mut self) -> f64 {
        let now = std::time::Instant::now();
        self.tokens = (self.tokens
            + now
                .saturating_duration_since(self.last_refill)
                .as_secs_f64()
                * self.refill_per_second)
            .min(self.capacity);
        self.last_refill = now;
        self.tokens
    }
}

pub(super) fn admit_firewall_request_ip(
    cooldowns: &mut HashMap<Ipv4Addr, i64>,
    ip: Ipv4Addr,
    now: i64,
) -> bool {
    if cooldowns.len() >= MAX_FIREWALL_REQ_COOLDOWN_ENTRIES {
        cooldowns.retain(|_, ts| now.saturating_sub(*ts) < FIREWALL_REQ_COOLDOWN_SECS);
    }
    if cooldowns.len() >= MAX_FIREWALL_REQ_COOLDOWN_ENTRIES && !cooldowns.contains_key(&ip) {
        return false;
    }
    if cooldowns
        .get(&ip)
        .is_some_and(|previous| now.saturating_sub(*previous) < FIREWALL_REQ_COOLDOWN_SECS)
    {
        return false;
    }
    cooldowns.insert(ip, now);
    true
}

/// Minimum number of *verified* routing-table contacts before we report the
/// KAD status as `Connected`. `routing_table.len()` also counts unverified
/// contacts (e.g. loaded from `nodes.dat` or learned from FindNode responses
/// but never confirmed); a table that holds only unverified contacts can't
/// actually route, since `find_closest` returns verified contacts only. Gating
/// on at least one verified contact keeps the reported status honest — we
/// don't claim to be on the network until we have a contact we can really
/// reach.
pub(super) const KAD_MIN_VERIFIED_FOR_CONNECTED: usize = 1;

/// True when we have decoded a KAD packet recently enough to claim Connected.
/// Prevents bootstrap from promoting on stale `nodes.dat` verified rows after
/// KADEMLIADISCONNECTDELAY cleared `last_kad_contact`.
pub(super) fn kad_has_fresh_contact(state: &NetworkState) -> bool {
    const KAD_DISCONNECT_DELAY_SECS: i64 = 1200;
    match state.last_kad_contact {
        Some(ts) => chrono::Utc::now().timestamp().saturating_sub(ts) <= KAD_DISCONNECT_DELAY_SECS,
        None => false,
    }
}

/// Backoff interval (seconds) before the periodic bootstrap timer is allowed
/// to re-blast `bootstrap::default_bootstrap_contacts()` — the handful of
/// long-running public eMule KAD seed IPs — again. `shift` is how many times
/// we've already sent the blast since the last successful `Connected`
/// transition (or process start).
///
/// eMule's own `CKademlia::Process()` pops one bootstrap contact at a time no
/// more than every 15s (2s only while the routing table is completely empty)
/// and stops entirely once its bootstrap list is exhausted — it never
/// re-hits the same well-known IPs forever. We don't have that "give up"
/// behavior (this is the only fallback for a client with no nodes.dat and no
/// live contacts), so instead we grow the interval each time we send:
/// 10s, 20s, 40s, ..., capped at 10 minutes once `shift` reaches 6. Without
/// this, a client that's permanently offline or UDP-firewalled would hammer
/// the same 5 public IPs every 10s indefinitely for as long as the app runs.
pub(super) fn hardcoded_bootstrap_backoff_interval(shift: u32) -> i64 {
    const BASE_SECS: i64 = 10;
    const MAX_SECS: i64 = 10 * 60;
    BASE_SECS.saturating_mul(1i64 << shift.min(6)).min(MAX_SECS)
}

pub(super) const MAX_BOOTSTRAP_CONTACTS: usize = 1_000;

pub(super) fn applied_bootstrap_contact_count(parsed_count: usize) -> usize {
    parsed_count.min(MAX_BOOTSTRAP_CONTACTS)
}

pub(super) fn count_accepted_bootstrap_contacts<T>(
    contacts: impl IntoIterator<Item = T>,
    mut insert: impl FnMut(T) -> bool,
) -> usize {
    contacts
        .into_iter()
        .map(|contact| usize::from(insert(contact)))
        .sum()
}

/// Charge a plaintext KAD packet to the per-destination request budget (see
/// `kad::outbound`). False when sending it now would put `addr` over eMule's
/// request-flood limit for its opcode.
pub(super) fn kad_request_allowed(state: &NetworkState, addr: SocketAddr, packet: &[u8]) -> bool {
    kad_requests_allowed(state, addr, packet, 1)
}

/// [`kad_request_allowed`] for `count` packets of `packet`'s opcode at once:
/// all are charged or none are. Pair with [`send_prepaid_kad_packet`].
pub(super) fn kad_requests_allowed(
    state: &NetworkState,
    addr: SocketAddr,
    packet: &[u8],
    count: usize,
) -> bool {
    match kad::outbound::kad_packet_opcode(packet) {
        Some(opcode) => state.kad_outbound.lock().allow_many(addr.ip(), opcode, count),
        None => true,
    }
}

/// Whether a request with `opcode` could go to `addr` now and none has gone
/// there within `min_gap`. Charges nothing.
pub(super) fn kad_request_ready(
    state: &NetworkState,
    addr: SocketAddr,
    opcode: u8,
    min_gap: std::time::Duration,
) -> bool {
    let governor = state.kad_outbound.lock();
    governor.would_allow(addr.ip(), opcode)
        && governor
            .since_last(addr.ip(), opcode)
            .is_none_or(|age| age >= min_gap)
}

/// The error [`send_kad_packet`] / [`send_kad_response`] return for a
/// request the per-destination budget held back. Nothing was sent; unlike a
/// socket error, retrying the same destination at once cannot succeed.
pub(super) fn is_kad_request_paced(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
}

fn kad_request_paced(addr: SocketAddr, packet: &[u8]) -> std::io::Error {
    debug!(
        "KAD request 0x{:02X} to {addr} deferred: per-destination budget spent",
        packet.get(1).copied().unwrap_or(0)
    );
    std::io::Error::new(std::io::ErrorKind::WouldBlock, "KAD request pacing")
}

/// Send a KAD packet, optionally using obfuscation if the target supports it
/// and the user has enabled protocol obfuscation in settings.
///
/// Requests over the destination's budget are not sent and return
/// `ErrorKind::WouldBlock`.
pub(super) async fn send_kad_packet(
    socket: &UdpSocket,
    packet: &[u8],
    addr: SocketAddr,
    state: &NetworkState,
    target_id: &KadId,
) -> std::io::Result<usize> {
    if !kad_request_allowed(state, addr, packet) {
        return Err(kad_request_paced(addr, packet));
    }
    send_prepaid_kad_packet(socket, packet, addr, state, target_id).await
}

/// [`send_kad_packet`] for a packet already charged with
/// [`kad_requests_allowed`].
pub(super) async fn send_prepaid_kad_packet(
    socket: &UdpSocket,
    packet: &[u8],
    addr: SocketAddr,
    state: &NetworkState,
    target_id: &KadId,
) -> std::io::Result<usize> {
    let contact = state.routing_table.get_contact(target_id);
    let use_obfuscation =
        state.obfuscation_enabled && contact.is_some_and(|c| c.supports_obfuscation());

    let result = if use_obfuscation {
        let their_ip = match addr.ip() {
            std::net::IpAddr::V4(ip) => u32::from(ip),
            _ => 0,
        };
        let sender_key = KadUDPKey::verify_key_for(state.udp_key_seed, their_ip);
        // The peer's key is bound to *our* address, not theirs, so echo it back
        // against our own public IP.
        let receiver_key_val = contact
            .and_then(|c| c.udp_key)
            .filter(|k| k.is_valid())
            .map(|k| k.value_for(state.external_ip.map(u32::from)))
            .unwrap_or(0);
        let encrypted =
            obfuscation::encrypt_kad_packet(packet, target_id, sender_key, receiver_key_val);
        socket.send_to(&encrypted, addr).await
    } else {
        socket.send_to(packet, addr).await
    };
    match &result {
        Ok(n) => {
            if *n > 0 {
                state
                    .kad_upload_overhead
                    .fetch_add(*n as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }
        Err(e) => {
            debug!("UDP send to {addr} failed: {e}");
        }
    }
    result
}

/// Send an Ember-native UDP datagram and count its on-wire bytes against
/// the given overhead counter (EPX or Ember DHT). Matches
/// [`send_kad_packet`]'s accounting: only successful `send_to` lengths
/// are recorded, so a failed send cannot inflate the Statistics page.
pub(super) async fn send_ember_udp(
    socket: &UdpSocket,
    packet: &[u8],
    addr: SocketAddr,
    overhead: &crate::storage::statistics::SharedSxOverheadCounters,
) -> std::io::Result<usize> {
    let result = socket.send_to(packet, addr).await;
    if let Ok(n) = result {
        overhead.record_upload(n as u64);
    }
    result
}

pub(super) fn from_ip_v4(from: SocketAddr) -> Option<Ipv4Addr> {
    match from.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

/// Resolve the publisher identity for keyword-index accounting when the
/// publish packet has no wire client hash (PublishKeyReq). Derive a stable
/// ID from `(ip, port)` so one address cannot rotate claimed IDs to occupy
/// many logical publisher slots. Source/Notes publishes use the wire
/// `sender_id` directly (eMule `m_uSourceID.SetValue(uTarget)`).
pub(super) fn resolve_keyword_publisher_id(state: &NetworkState, from: SocketAddr) -> KadId {
    let v4 = match from.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => return KadId::zero(),
    };
    if let Some(c) = state
        .routing_table
        .all_contacts()
        .find(|c| c.ip == v4 && c.udp_port == from.port())
    {
        return c.id;
    }
    use digest::Digest;
    let mut h = md5::Md5::new();
    h.update(b"ember-kad-unknown-sender-v1");
    h.update(v4.octets());
    h.update(from.port().to_le_bytes());
    let digest = h.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest);
    KadId(bytes)
}

/// eMule Hello challenge when a contact lacks a valid receiver UDP key:
/// - Kad < 7: `KADEMLIA2_REQ` with a random target (legacy challenge)
/// - Kad == 7: Ping challenge
/// - Kad ≥ 8 with obfuscation disabled: Req challenge (plaintext verify path;
///   HelloResAck cannot prove identity without crypt)
pub(super) async fn maybe_send_hello_challenge(
    socket: &UdpSocket,
    from: SocketAddr,
    ip: Ipv4Addr,
    contact_id: KadId,
    version: u8,
    state: &mut NetworkState,
    peer_udp_key: Option<KadUDPKey>,
) {
    if state.legacy_challenges.has_active(ip) {
        return;
    }

    if version < KADEMLIA_VERSION7_49A
        || (version >= KADEMLIA_VERSION8_49B && !state.obfuscation_enabled)
    {
        let mut challenge = KadId::random();
        if challenge == KadId::zero() {
            challenge = KadId::from_u32(1);
        }
        let req = KadMessage::KadReq {
            search_type: messages::KADEMLIA_FIND_VALUE,
            target: challenge,
            receiver: contact_id,
        };
        if let Ok(packet) = messages::encode_packet(&req) {
            // Registered only once the challenge is out: an active challenge
            // suppresses the next one for its whole lifetime, so one the
            // budget held back would leave the contact unverifiable until then.
            if send_kad_response(socket, &packet, from, state, Some(&contact_id), peer_udp_key)
                .await
                .is_ok()
            {
                state.legacy_challenges.add(
                    contact_id,
                    challenge,
                    ip,
                    LegacyChallengeTracker::OPCODE_REQ,
                );
                state
                    .flood_protection
                    .track_request(from, messages::KADEMLIA2_REQ);
                debug!("Sent legacy KadReq challenge to {from} (version={version})");
            }
        }
    } else if version == KADEMLIA_VERSION7_49A {
        let ping = KadMessage::Ping;
        if let Ok(packet) = messages::encode_packet(&ping) {
            if send_kad_response(socket, &packet, from, state, Some(&contact_id), peer_udp_key)
                .await
                .is_ok()
            {
                state.legacy_challenges.add(
                    contact_id,
                    KadId::zero(),
                    ip,
                    LegacyChallengeTracker::OPCODE_PING,
                );
                state.flood_protection.track_request(from, 0x60);
                debug!("Sent legacy Ping challenge to {from}");
            }
        }
    }
}

pub(super) async fn send_kad_response(
    socket: &UdpSocket,
    packet: &[u8],
    addr: SocketAddr,
    state: &NetworkState,
    target_id: Option<&KadId>,
    peer_udp_key: Option<KadUDPKey>,
) -> std::io::Result<usize> {
    // Responses pass untouched; the requests some callers send through here
    // (Hello challenges, legacy pings) are paced like any other.
    if !kad_request_allowed(state, addr, packet) {
        return Err(kad_request_paced(addr, packet));
    }
    let their_ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => u32::from(ip),
        _ => 0,
    };
    // A peer's key is bound to *our* public IP, so it is read back against that
    // rather than the peer's address.
    let our_public_ip = state.external_ip.map(u32::from);
    let receiver_key_val = peer_udp_key
        .filter(|k| k.is_valid())
        .map(|k| k.value_for(our_public_ip))
        .unwrap_or_else(|| {
            target_id
                .and_then(|id| state.routing_table.get_contact(id))
                .and_then(|c| c.udp_key)
                .filter(|k| k.is_valid())
                .map(|k| k.value_for(our_public_ip))
                .unwrap_or(0)
        });
    let target_kad_id = target_id.copied();
    // Obfuscate the response whenever we hold *any* usable key, not only when
    // we know the peer's KadID. eMule frequently replies keyed on the sender's
    // UDP verify key with no target KadID at all, so a peer that contacted us
    // obfuscated must get an obfuscated reply even when its KadID isn't on
    // hand. When only the verify key is available we encrypt under a zero
    // target KadID, which `encrypt_kad_packet` maps to eMule's
    // ReceiverVerifyKey path (marker 0x02). The previous `target_id.is_some()`
    // gate meant such peers silently got a plaintext reply.
    let use_obfuscation = state.obfuscation_enabled
        && (receiver_key_val != 0
            || target_id
                .and_then(|id| state.routing_table.get_contact(id))
                .map(|c| c.supports_obfuscation())
                .unwrap_or(false));
    let result = if use_obfuscation {
        // Zero KadID only ever pairs with a non-zero receiver key here (the
        // `supports_obfuscation` branch requires `target_id`), so this always
        // resolves to a valid eMule key path.
        let kad_id = target_kad_id.unwrap_or_else(KadId::zero);
        let sender_key = KadUDPKey::verify_key_for(state.udp_key_seed, their_ip);
        let encrypted =
            obfuscation::encrypt_kad_packet(packet, &kad_id, sender_key, receiver_key_val);
        socket.send_to(&encrypted, addr).await
    } else {
        socket.send_to(packet, addr).await
    };
    if let Err(e) = &result {
        debug!("UDP response to {addr} failed: {e}");
    }
    result
}

pub(super) fn kad_request_opcode(msg: &KadMessage) -> Option<u8> {
    match msg {
        KadMessage::BootstrapReq => Some(kad::messages::KADEMLIA2_BOOTSTRAP_REQ),
        KadMessage::HelloReq { .. } => Some(kad::messages::KADEMLIA2_HELLO_REQ),
        KadMessage::HelloRes { .. } => Some(kad::messages::KADEMLIA2_HELLO_RES),
        KadMessage::KadReq { .. } => Some(kad::messages::KADEMLIA2_REQ),
        KadMessage::SearchKeyReq { .. } => Some(kad::messages::KADEMLIA2_SEARCH_KEY_REQ),
        KadMessage::SearchSourceReq { .. } => Some(kad::messages::KADEMLIA2_SEARCH_SOURCE_REQ),
        KadMessage::SearchNotesReq { .. } => Some(kad::messages::KADEMLIA2_SEARCH_NOTES_REQ),
        KadMessage::PublishKeyReq { .. } => Some(kad::messages::KADEMLIA2_PUBLISH_KEY_REQ),
        KadMessage::PublishSourceReq { .. } => Some(kad::messages::KADEMLIA2_PUBLISH_SOURCE_REQ),
        KadMessage::PublishNotesReq { .. } => Some(kad::messages::KADEMLIA2_PUBLISH_NOTES_REQ),
        KadMessage::FindBuddyReq { .. } => Some(kad::messages::KADEMLIA_FINDBUDDY_REQ),
        KadMessage::CallbackReq { .. } => Some(kad::messages::KADEMLIA_CALLBACK_REQ),
        KadMessage::Ping => Some(kad::messages::KADEMLIA2_PING),
        _ => None,
    }
}

pub(super) async fn send_kad_search_results(
    socket: &UdpSocket,
    addr: SocketAddr,
    state: &NetworkState,
    sender_id: KadId,
    target: KadId,
    results: &[kad::messages::SearchResultEntry],
    peer_udp_key: Option<KadUDPKey>,
) {
    if results.is_empty() {
        return;
    }

    const HEADER_OVERHEAD: usize = 50;
    const MAX_BATCH: usize = kad::messages::UDP_KAD_MAXFRAGMENT;
    let mut batch: Vec<kad::messages::SearchResultEntry> = Vec::new();
    let mut batch_est_size: usize = HEADER_OVERHEAD;

    for entry in results {
        // Size each tag by what it actually serializes to. The old flat
        // 24-bytes-per-tag figure ignored string payloads, and a stored
        // keyword entry's filename may run to `MAX_STORED_FILENAME_BYTES`
        // (4 KiB) — so a "1420-byte" batch of long-named hits was really
        // several KB, `encode_packet` could not compress it under the
        // fragment ceiling, and the error was discarded along with every
        // result in the batch. A publisher could plant long filenames under
        // a keyword we store for and blind our answers for it.
        let entry_est: usize = 16
            + 8
            + entry
                .tags
                .iter()
                .map(|tag| match &tag.value {
                    kad::types::TagValue::String(s) => s.len() + 6,
                    _ => 12,
                })
                .sum::<usize>();
        if batch_est_size + entry_est > MAX_BATCH && !batch.is_empty() {
            let msg = KadMessage::SearchRes {
                sender_id,
                target,
                results: std::mem::take(&mut batch),
            };
            if let Ok(packet) = messages::encode_packet(&msg) {
                let _ = send_kad_response(socket, &packet, addr, state, None, peer_udp_key).await;
            }
            batch_est_size = HEADER_OVERHEAD;
        }
        batch_est_size += entry_est;
        batch.push(entry.clone());
    }

    if !batch.is_empty() {
        let msg = KadMessage::SearchRes {
            sender_id,
            target,
            results: batch,
        };
        if let Ok(packet) = messages::encode_packet(&msg) {
            let _ = send_kad_response(socket, &packet, addr, state, None, peer_udp_key).await;
        }
    }
}

pub(super) fn build_kad_connect_options(state: &NetworkState) -> u8 {
    let supports_crypt = state.obfuscation_enabled as u8;
    let requests_crypt = state.obfuscation_enabled as u8;
    let requires_crypt = 0u8;
    let direct_udp_callback = can_advertise_direct_udp_callback(state) as u8;
    (direct_udp_callback << 3) | (requires_crypt << 2) | (requests_crypt << 1) | supports_crypt
}

pub(super) fn can_advertise_direct_udp_callback(state: &NetworkState) -> bool {
    state.firewalled
        && !state.udp_firewalled
        && state.udp_fw_verified
        && state.external_ip.is_some()
        && state.external_udp_port.unwrap_or(state.udp_port) != 0
}

/// Mutate `state.external_ip` AND publish the change to the shared atomic
/// that long-lived subsystems (e.g. the upload listener's HelloAnswer path)
/// read without holding a lock. Always use this instead of assigning to
/// `state.external_ip` directly so the two views never drift. `None` clears
/// the atomic back to `0`, which the Hello builder interprets as "advertise
/// client_id=0 and let the peer's BaseClient auto-heal from the connect IP"
/// — correct fallback behavior when we don't yet have a trusted public IP.
///
/// The routing table is updated here too: KAD contact UDP keys are bound to our
/// public address, so a table left on a stale IP would judge every stored key
/// against the wrong one.
/// HighID from a live ed2k server TCP connect-back, if it is a plausible IP.
pub(super) fn live_highid_external_ip(state: &NetworkState) -> Option<Ipv4Addr> {
    if !state.server_connected || state.low_id {
        return None;
    }
    if state.server_client_id < ed2k::server::LOWID_THRESHOLD {
        return None;
    }
    let ip = Ipv4Addr::from(state.server_client_id.to_le_bytes());
    if crate::security::is_bogus_v4(ip) {
        return None;
    }
    Some(ip)
}

/// Whether a STUN-mapped IPv4 should become `external_ip`.
///
/// STUN is a first-party measurement and may replace a KAD/Ember vote that
/// won the startup race. It must not replace a live HighID: that address was
/// proven by TCP connect-back and can differ from the UDP mapping.
pub(super) fn should_adopt_stun_external_ip(
    current: Option<Ipv4Addr>,
    stun_ip: Ipv4Addr,
    highid: Option<Ipv4Addr>,
) -> bool {
    if crate::security::is_bogus_v4(stun_ip) {
        return false;
    }
    if current == Some(stun_ip) {
        return false;
    }
    if let Some(highid) = highid {
        if current == Some(highid) {
            return false;
        }
    }
    true
}

pub(super) fn adopt_stun_mapped_external_ip(state: &mut NetworkState, ip: Ipv4Addr) {
    if !should_adopt_stun_external_ip(state.external_ip, ip, live_highid_external_ip(state)) {
        return;
    }
    info!(
        "External IP set from STUN: {} (was {:?})",
        ip, state.external_ip
    );
    set_external_ip(state, Some(ip));
    state.stats.external_ip = ip.to_string();
}

/// Whether reachability evidence earned while our external address was
/// `earned_under` still holds once the address becomes `new_ip`.
///
/// Only a move to a different known address invalidates it. An address that
/// is merely unknown for a while has not moved: KAD disconnect clears it until
/// STUN reports the same one again.
pub(super) fn reach_evidence_survives(
    earned_under: Option<Ipv4Addr>,
    new_ip: Option<Ipv4Addr>,
) -> bool {
    match new_ip {
        None => true,
        Some(ip) => earned_under == Some(ip),
    }
}

pub(super) fn set_external_ip(state: &mut NetworkState, ip: Option<Ipv4Addr>) {
    if state.external_ip != ip {
        state.server_list.invalidate_udp_keys_for_public_ip(ip);
        // An Ember source record embeds the address peers should dial, and is
        // only re-announced once `EMBER_SOURCE_REPUBLISH` has elapsed, so after
        // a DHCP lease change or an ISP reconnection every record we had placed
        // would send downloaders to whoever holds the old address for up to two
        // hours. Measured against the address those records were published
        // under, not against `external_ip`: that starts out unknown and is
        // cleared by a KAD disconnect, and an address that is unknown for a
        // while has not moved. Keyword records carry no address, so their
        // schedule is deliberately untouched.
        if let Some(new_ip) = ip {
            note_ember_source_address(state, new_ip);
        }
        // Whatever proved our port was open, proved it about the old address.
        // A new address can mean a new NAT, a new router, or a different
        // network entirely, so the evidence has to be earned again rather than
        // coasting to the end of its TTL — including the first witness, which is
        // half of that evidence.
        if !reach_evidence_survives(state.ember_reach_external_ip, ip) {
            state.ember_udp_reachable_at = None;
            state.ember_reach_witness = None;
        }
        // Rendezvous failures earned on the old address say nothing about the
        // new one, and presence has to be re-announced from it promptly. A
        // transient `None` keeps the backoff; the disconnect path covers that.
        if ip.is_some() {
            state.rendezvous_register_fail_streak = 0;
            state.rendezvous_last_attempt = None;
        }
    }
    state.external_ip = ip;
    state.routing_table.set_external_ip(ip);
    let client_id_le = match ip {
        Some(v4) => u32::from_le_bytes(v4.octets()),
        None => 0,
    };
    state
        .external_ip_shared
        .store(client_id_le, std::sync::atomic::Ordering::Relaxed);
}

/// Whether KAD *source* publishes must use the firewalled (buddy / type-6)
/// path. Keywords still publish either way; `build_source_publish` returns
/// `None` until a buddy or verified UDP callback exists.
///
/// TCP `Unknown` counts as firewalled so we never advertise a type-1/4
/// source before inbound TCP is proven. Callers must therefore refresh the
/// publish manager *after* `handle_tcp_connect_back`, not before.
pub(super) fn kad_source_publish_treat_as_firewalled(
    low_id: bool,
    tcp_status: crate::network::kad::firewall::FirewallStatus,
) -> bool {
    low_id || tcp_status != crate::network::kad::firewall::FirewallStatus::Open
}

pub(super) fn update_publish_manager_state(state: &mut NetworkState) {
    // Source/callback publishes follow TCP reachability, not the UPnP-cleared
    // UI badge. A LowID or a TCP check that is not Open means peers cannot
    // dial us, so we publish as firewalled even when the router mapping looks
    // healthy.
    state.publish_manager.firewalled = kad_source_publish_treat_as_firewalled(
        state.low_id,
        state.firewall_checker.tcp_status(),
    );
    state.publish_manager.udp_port = advertised_udp_port(state);
    state.publish_manager.use_extern_kad_port = state.publish_manager.udp_port != state.udp_port;
    state.publish_manager.tcp_port = advertised_tcp_port(state);
    // BuddyManager bakes tcp_port/udp_port in at construction (buddy Hello
    // handshake / OP_CALLBACK payloads) with no other refresh path — without
    // this, a mid-session STUN remap would never reach the buddy protocol.
    state
        .buddy_manager
        .set_tcp_port(state.publish_manager.tcp_port);
    state
        .buddy_manager
        .set_udp_port(state.publish_manager.udp_port);
    state.advertise_tcp_port.store(
        state.publish_manager.tcp_port,
        std::sync::atomic::Ordering::Relaxed,
    );
    ed2k::peer_sessions::set_advertised_tcp_port(state.publish_manager.tcp_port);
    state.advertise_udp_port.store(
        state.publish_manager.udp_port,
        std::sync::atomic::Ordering::Relaxed,
    );
    state.publish_manager.direct_udp_callback = can_advertise_direct_udp_callback(state);
    state.publish_manager.connect_options = build_kad_connect_options(state);

    if let Some(buddy) = state.buddy_manager.buddy_id().cloned() {
        state.publish_manager.buddy_id = Some(buddy);
        if let Some((ip, tcp_port)) = state.buddy_manager.buddy_addr() {
            // TAG_SERVERIP uses eMule's "LSB-first" host-integer convention:
            // the eMule receiver does `dwBuddyIP = cTag.GetInt()` with NO
            // `htonl` (unlike TAG_SOURCEIP, which IS htonl'd in
            // DownloadQueue::KademliaSearchFile). For an IP whose dotted-quad
            // octets are `[a,b,c,d]`, eMule expects the wire-decoded uint32
            // to equal `0xddccbbaa` so that `ipstr()` (which prints LSB-first)
            // displays `a.b.c.d`. Our Uint32 tag is LE-encoded on the wire, so
            // the byte sequence `[a,b,c,d]` corresponds to `from_le_bytes`,
            // NOT `from_be_bytes`. Using `from_be_bytes` here would publish
            // every buddy IP byte-reversed — turning a real residential
            // 88.147.30.21 into the unroutable 21.30.147.88 — so any peer
            // trying to call us back via our buddy would dial a dead address.
            // The parse side (`extract_kad_sources` for TAG_SERVERIP) mirrors
            // this with `.to_le_bytes()`; the two must stay in sync.
            state.publish_manager.buddy_ip = u32::from_le_bytes(ip.octets());
            // The port a searcher sends `KADEMLIA_CALLBACK_REQ` to, which is
            // the buddy's Kad UDP socket — recorded from its `FindBuddyRes`,
            // the way eMule's `Search.cpp` publishes `GetBuddy()->GetUDPPort()`.
            //
            // This used to look the buddy up in the routing table by
            // `buddy_manager.buddy_id()`, which is the FindBuddy *search
            // target* `NOT(local_kad_id)` rather than the buddy's node ID, so
            // the lookup could never hit and every publish fell through to the
            // guess below. That guess was also `tcp + 3`, an eDonkey-era
            // 4662/4665 convention; the eMule pair is 4662/4672.
            let buddy_udp = state.buddy_manager.buddy_udp_port().unwrap_or_else(|| {
                tcp_port.saturating_add(
                    kad::types::DEFAULT_UDP_PORT - kad::types::DEFAULT_TCP_PORT,
                )
            });
            state.publish_manager.buddy_port = buddy_udp;
        }
    } else {
        state.publish_manager.buddy_id = None;
        state.publish_manager.buddy_ip = 0;
        state.publish_manager.buddy_port = 0;
    }
}

/// Upper bound on buffered fresh UDP-firewall probe candidates. eMule keeps a
/// small `m_liPossibleTestClients` list; we allow a few more for reliability.
pub(super) const UDP_FW_CANDIDATE_POOL_MAX: usize = 64;

pub(super) fn dispatch_udp_firewall_probe_requests(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    settings: &AppSettings,
) {
    if !state.firewall_checker.needs_udp_firewall_probes() {
        // Test finished/inactive: drop leftover fresh candidates and forget the
        // scratch lookup so the next cycle starts clean (eMule
        // CUDPFirewallTester clears m_liPossibleTestClients and cancels the
        // NODEFWCHECKUDP search when the test concludes).
        state.udp_fw_candidate_pool.clear();
        state.udp_fw_node_search = None;
        return;
    }

    // eMule CSearchManager::FindNodeFWCheckUDP: seed a random-target node lookup
    // whose *discovered* contacts we only ever reach over TCP, so they are
    // guaranteed to be IPs we have never sent a KAD UDP packet to. Probing
    // already-known routing-table peers can yield a false "UDP open" verdict
    // behind a restricted-cone NAT (a UDP mapping to that peer may already
    // exist from earlier Kad traffic).
    let fw_search_active = match state.udp_fw_node_search {
        Some(sid) => state
            .search_manager
            .get(&sid)
            .map(|s| !s.completed)
            .unwrap_or(false),
        None => false,
    };
    if !fw_search_active {
        state.udp_fw_node_search = None;
        if state.udp_fw_candidate_pool.is_empty() {
            let target = KadId::random();
            let closest = state
                .routing_table
                .find_closest_prefer_verified(&target, SEARCH_INITIAL_CONTACTS);
            if !closest.is_empty() {
                let sid =
                    start_kad_search(state, app_handle, target, SearchType::FindNode, closest);
                if sid != SearchId(0) {
                    if let Some(s) = state.search_manager.get_mut(&sid) {
                        s.is_udp_fw_probe_search = true;
                    }
                    state.udp_fw_node_search = Some(sid);
                    debug!(
                        "Started fresh-node lookup {} to seed UDP firewall probe candidates",
                        sid.0
                    );
                }
            }
        }
    }

    let external_udp_port = state
        .firewall_checker
        .external_udp_port()
        .filter(|&p| p > 0)
        .or(state.external_udp_port)
        .unwrap_or(settings.udp_port);

    // Draw probe targets exclusively from the fresh candidate pool. Skip
    // ourselves, anything already probed this cycle, anything that has since
    // entered the routing table (now UDP-contacted), and filtered/banned IPs.
    let self_ip = state.external_ip;
    let mut contacts: Vec<KadContact> = Vec::new();
    while contacts.len() < 4 {
        let Some(candidate) = state.udp_fw_candidate_pool.pop_front() else {
            break;
        };
        if Some(candidate.ip) == self_ip
            || candidate.tcp_port == 0
            || candidate.version <= KADEMLIA_VERSION5_48A
            || state
                .firewall_checker
                .is_udp_firewall_check_ip(candidate.ip)
            || state.routing_table.get_contact(&candidate.id).is_some()
            || state.ip_filter.is_blocked_readonly_for_kad(candidate.ip)
            || state.banned_ips.contains(&candidate.ip)
        {
            continue;
        }
        contacts.push(candidate);
    }

    if !contacts.is_empty() {
        info!(
            "Dispatching {} UDP firewall probe(s) (ext_udp_port={})",
            contacts.len(),
            external_udp_port
        );
    }
    let external_ip = state.external_ip;
    let obfuscation_enabled = settings.obfuscation_enabled;
    for contact in contacts {
        state
            .firewall_checker
            .record_udp_firewall_request_sent(contact.ip);
        spawn_udp_firewall_probe_request(
            contact,
            state.user_hash,
            settings.nickname.clone(),
            advertised_tcp_port(state),
            advertised_udp_port(state),
            external_udp_port,
            state.udp_key_seed,
            external_ip,
            obfuscation_enabled,
        );
    }
}

pub(super) fn spawn_udp_firewall_probe_request(
    contact: KadContact,
    user_hash: [u8; 16],
    nickname: String,
    tcp_port: u16,
    udp_port: u16,
    external_udp_port: u16,
    udp_key_seed: u32,
    external_ip: Option<Ipv4Addr>,
    obfuscation_enabled: bool,
) {
    let contact_ip = contact.ip;
    let contact_tcp = contact.tcp_port;
    tokio::spawn(async move {
        match send_udp_firewall_probe_request(
            contact,
            user_hash,
            nickname,
            tcp_port,
            udp_port,
            external_udp_port,
            udp_key_seed,
            external_ip,
            obfuscation_enabled,
        )
        .await
        {
            Ok(()) => debug!(
                "UDP firewall probe sent to {}:{} (asking for reply on ports {}/{})",
                contact_ip, contact_tcp, udp_port, external_udp_port
            ),
            // Probe failures are routine — Windows surfaces remote
            // ICMP-unreachable as `os error 10054`, which just means the
            // peer's UDP port is closed (very common for stale routing
            // contacts). Each cycle dispatches several probes and we
            // only need *one* successful peer to confirm not-firewalled,
            // so per-probe failures are debug-only. The aggregate
            // outcome is logged separately as "UDP firewall test
            // passed/failed".
            Err(e) => debug!(
                "UDP firewall probe to {}:{} failed: {e}",
                contact_ip, contact_tcp
            ),
        }
    });
}

pub(super) async fn send_udp_firewall_probe_request(
    contact: KadContact,
    user_hash: [u8; 16],
    nickname: String,
    tcp_port: u16,
    udp_port: u16,
    external_udp_port: u16,
    udp_key_seed: u32,
    external_ip: Option<Ipv4Addr>,
    obfuscation_enabled: bool,
) -> anyhow::Result<()> {
    let addr = SocketAddr::new(contact.ip.into(), contact.tcp_port);
    let stream = tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("TCP connect timeout to {addr}"))??;
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    let our_client_id = external_ip
        .map(|ip| u32::from_le_bytes(ip.octets()))
        .unwrap_or(0);
    // Same crypt claims as every other Hello we send: the default options
    // advertise obfuscation even for a user who turned it off.
    let mut hello_options = ed2k::messages::HelloOptions::default_for_udp_port(udp_port);
    hello_options.supports_crypt_layer = obfuscation_enabled;
    hello_options.requests_crypt_layer = obfuscation_enabled;
    let hello = ed2k::messages::build_hello_with_buddy_opts(
        &user_hash,
        our_client_id,
        tcp_port,
        &nickname,
        None,
        &hello_options,
    );
    write_ed2k_packet_simple(
        &mut writer,
        OP_EDONKEYHEADER,
        ed2k::messages::OP_HELLO,
        &hello,
    )
    .await?;

    let (proto, opcode, hello_answer) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_ed2k_packet_simple(&mut reader),
    )
    .await
    .map_err(|_| anyhow::anyhow!("HelloAnswer timeout from {addr}"))??;
    if proto != OP_EDONKEYHEADER || opcode != ed2k::messages::OP_HELLOANSWER {
        anyhow::bail!(
            "expected HelloAnswer from {addr}, got proto=0x{proto:02X} op=0x{opcode:02X}"
        );
    }

    let needs_mule_info = ed2k::messages::parse_hello_answer(&hello_answer)
        .is_ok_and(|(hash, caps)| ed2k::messages::dialer_needs_mule_info(&hash, &caps));
    if needs_mule_info {
        let emule_info =
            ed2k::messages::build_emule_info(udp_port, obfuscation_enabled, None, None);
        write_ed2k_packet_simple(
            &mut writer,
            OP_EMULEPROT,
            ed2k::messages::OP_EMULEINFO,
            &emule_info,
        )
        .await?;

        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_ed2k_packet_simple(&mut reader),
        )
        .await;
    }

    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&udp_port.to_le_bytes());
    payload.extend_from_slice(&external_udp_port.to_le_bytes());
    let receiver_key = KadUDPKey::verify_key_for(udp_key_seed, u32::from(contact.ip));
    payload.extend_from_slice(&receiver_key.to_le_bytes());
    write_ed2k_packet_simple(
        &mut writer,
        OP_EMULEPROT,
        ed2k::messages::OP_FWCHECKUDPREQ,
        &payload,
    )
    .await?;
    // Give the remote peer time to read and process the request before
    // we drop the TCP connection.  Without this, some clients abort
    // processing when they see the connection close immediately.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    Ok(())
}

pub(super) async fn send_kad_udp_firewall_result(
    socket: &UdpSocket,
    state: &NetworkState,
    peer_ip: Ipv4Addr,
    internal_udp_port: u16,
    external_udp_port: u16,
    receiver_udp_key: u32,
) {
    let mut ports = vec![internal_udp_port];
    if external_udp_port != 0 && external_udp_port != internal_udp_port {
        ports.push(external_udp_port);
    }

    for port in ports {
        if port == 0 {
            continue;
        }
        let msg = KadMessage::FirewallUdp {
            error_code: 0,
            udp_port: port,
        };
        let Ok(packet) = messages::encode_packet(&msg) else {
            continue;
        };
        let addr = SocketAddr::new(peer_ip.into(), port);
        let result = if receiver_udp_key != 0 {
            let sender_key = KadUDPKey::verify_key_for(state.udp_key_seed, u32::from(peer_ip));
            let encrypted = obfuscation::encrypt_kad_packet(
                &packet,
                &KadId::zero(),
                sender_key,
                receiver_udp_key,
            );
            socket.send_to(&encrypted, addr).await
        } else {
            socket.send_to(&packet, addr).await
        };
        if let Err(e) = result {
            debug!("Failed to send FirewallUdp result to {addr}: {e}");
        }
    }
}

pub(super) async fn read_ed2k_packet_simple(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let protocol = reader.read_u8().await?;
    let length = reader.read_u32_le().await? as usize;
    if length == 0 || length > 5_000_000 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid packet length: {length}"),
        ));
    }
    let opcode = reader.read_u8().await?;
    let payload_len = length.saturating_sub(1);
    // Grow on the heap in bounded steps with bytes that actually arrive rather
    // than trusting the declared length up front (avoids a stalled peer pinning
    // a multi-MiB allocation). Reading directly into the Vec — instead of via a
    // 64 KiB stack array — keeps this read's frame small, since it's awaited
    // inside large network futures where a big stack buffer can overflow the
    // worker stack in debug builds.
    let mut payload = Vec::new();
    let mut remaining = payload_len;
    const READ_STEP: usize = 65536;
    while remaining > 0 {
        let want = remaining.min(READ_STEP);
        let start = payload.len();
        payload.resize(start + want, 0);
        reader.read_exact(&mut payload[start..start + want]).await?;
        remaining -= want;
    }
    Ok((protocol, opcode, payload))
}

pub(super) async fn write_ed2k_packet_simple(
    writer: &mut BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    protocol: u8,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let length = (1 + payload.len()) as u32;
    writer.write_u8(protocol).await?;
    writer.write_u32_le(length).await?;
    writer.write_u8(opcode).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod firewall_request_bound_tests {
    use super::*;

    #[test]
    fn cooldown_map_never_exceeds_hard_cap() {
        let mut cooldowns = HashMap::new();
        for index in 0..MAX_FIREWALL_REQ_COOLDOWN_ENTRIES {
            cooldowns.insert(Ipv4Addr::new(10, (index >> 8) as u8, index as u8, 1), 100);
        }
        assert!(!admit_firewall_request_ip(
            &mut cooldowns,
            Ipv4Addr::new(203, 0, 113, 1),
            100
        ));
        assert_eq!(cooldowns.len(), MAX_FIREWALL_REQ_COOLDOWN_ENTRIES);
    }

    #[test]
    fn token_bucket_rejects_after_burst() {
        let mut bucket = TokenBucket::new(2, 0.0);
        assert!(bucket.try_take());
        assert!(bucket.try_take());
        assert!(!bucket.try_take());
    }

    #[test]
    fn token_bucket_reports_stress_without_consuming() {
        let mut bucket = TokenBucket::new(10, 0.0);
        assert!(bucket.available_tokens() >= 8.0);
        for _ in 0..9 {
            assert!(bucket.try_take());
        }
        assert!(bucket.available_tokens() < 8.0);
        assert!(bucket.try_take());
        assert!(!bucket.try_take());
    }
}

#[cfg(test)]
mod reach_evidence_tests {
    use super::*;

    const A: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
    const B: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);

    #[test]
    fn evidence_is_dropped_only_when_the_address_moves() {
        assert!(reach_evidence_survives(Some(A), Some(A)));
        assert!(!reach_evidence_survives(Some(A), Some(B)));
        // Unknown for a while is not a move.
        assert!(reach_evidence_survives(Some(A), None));
        assert!(reach_evidence_survives(None, None));
        // Evidence earned before we knew our address cannot vouch for the
        // first one we learn.
        assert!(!reach_evidence_survives(None, Some(A)));
    }

    /// Issue #124: disconnecting KAD showed a reachable node as relayed. KAD
    /// disconnect drops the external address until STUN reports it again, and
    /// that round trip wiped Ember's proof that the port is open.
    #[test]
    fn a_kad_disconnect_round_trip_keeps_the_node_reachable() {
        let now = 1_000_000i64;
        let proven_at = Some(now - 60);
        let earned_under = Some(A);
        assert!(reach_evidence_survives(earned_under, None));
        assert!(reach_evidence_survives(earned_under, Some(A)));
        assert!(ember_udp_reachable_from(
            ember::nat::NatType::PortRestricted,
            proven_at,
            now
        ));
    }
}
