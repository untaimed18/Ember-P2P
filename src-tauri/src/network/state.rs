//! `NetworkState`, the network task's mutable state, and the pending-request
//! structs it holds.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Returned by the network task when an outgoing Ember ping has been
/// scheduled. The Tauri command awaits the `pong_rx` oneshot with a
/// timeout to convert this into a final `EmberPingResult`.
///
/// Compiled out of release alongside `ember_ping_peer`, like its
/// `EmberDht*Pending` siblings below.
#[cfg(debug_assertions)]
#[derive(Debug)]
pub struct EmberPingPending {
    pub pong_rx: oneshot::Receiver<std::time::Duration>,
}

/// Returned by the network task when an outgoing Ember DHT `FIND_NODE`
/// has been scheduled. The Tauri command awaits `contacts_rx` with a
/// timeout; the waiter resolves with the contacts the peer returned.
#[cfg(debug_assertions)]
#[derive(Debug)]
pub struct EmberDhtFindPending {
    pub contacts_rx: oneshot::Receiver<Vec<EmberDhtContactInfo>>,
}

/// Returned by the network task when an iterative lookup has started.
/// The Tauri command awaits `contacts_rx` with a timeout; the waiter
/// resolves with the closest contacts that responded once the multi-hop
/// search converges.
#[cfg(debug_assertions)]
#[derive(Debug)]
pub struct EmberDhtLookupPending {
    pub contacts_rx: oneshot::Receiver<Vec<EmberDhtContactInfo>>,
}

/// Returned by the network task when a keyword publish has started. The
/// Tauri command awaits `result_rx` with a timeout; the waiter resolves
/// once every targeted node has acked, failed, or timed out.
#[derive(Debug)]
pub struct EmberPublishPending {
    /// The DHT key (hex) the record was published under, so the caller
    /// can later `FIND_VALUE` the same key. Only the harness publish
    /// command reads this; production channel publishes wait on
    /// `result_rx` alone.
    #[cfg(debug_assertions)]
    pub key: String,
    pub result_rx: oneshot::Receiver<EmberPublishResult>,
}

/// Outcome of a publish: how many of the targeted nodes stored the record.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EmberPublishResult {
    /// Nodes that acknowledged storing the record.
    pub stored_on: usize,
    /// Total nodes the record was sent to.
    pub targets: usize,
}

/// Tally of work kicked off by one Ember DHT maintenance cycle (slice 6).
/// The pings and refreshes resolve asynchronously afterwards (their
/// effects show up in the diagnostics counters and contact eviction); this
/// is the immediate "what did the cycle initiate" summary.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct EmberMaintenanceResult {
    /// Buckets for which a random-target refresh lookup was launched.
    pub buckets_refreshed: usize,
    /// Liveness `PING`s sent to stale contacts.
    pub liveness_pings_sent: usize,
    /// Locally-stored records re-published to the closest nodes.
    pub records_republished: usize,
    /// Records due for replication at the start of this cycle.
    pub republish_due: usize,
    /// How many of those the per-cycle budget selected.
    pub republish_selected: usize,
    /// Selected records the batch queue refused, put back on the schedule.
    pub republish_rearmed: usize,
    /// `ANNOUNCE_PEER` contact-list exchanges started this cycle.
    pub announces_sent: usize,
    /// KAD-bridge bootstrap `PING`s sent to KAD-learned Ember peers (slice
    /// 13). Non-zero only while the table is still sparse.
    pub kad_bridge_pings_sent: usize,
    /// Friend sessions asked for their Ember DHT contacts. Like the bridge,
    /// non-zero only while the table is short of a working set.
    pub friend_contact_asks: usize,
}

/// Persisted peak of verified Ember DHT contacts, so a restart does not
/// erase the only number that answers "is this table growing?".
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub(super) struct EmberVerifiedHighwater {
    /// UTC calendar day `daily` belongs to (`YYYY-MM-DD`).
    #[serde(default)]
    pub(super) day: String,
    #[serde(default)]
    pub(super) daily: u32,
    #[serde(default)]
    pub(super) alltime: u32,
}

/// Returned by the network task when an iterative `FIND_VALUE` lookup has
/// started. The Tauri command awaits `records_rx` with a timeout; the
/// waiter resolves with the verified records collected by the search.
#[derive(Debug)]
pub struct EmberValueLookupPending {
    pub search_id: u32,
    pub records_rx: oneshot::Receiver<Vec<Vec<u8>>>,
}

pub(super) struct PendingDownload {
    pub(super) transfer_id: String,
    pub(super) file_hash: String,
    pub(super) file_name: String,
    pub(super) file_size: u64,
    pub(super) expected_aich: Option<String>,
    pub(super) control: Arc<TransferControl>,
    pub(super) search_count: u32,
    pub(super) last_search_at: i64,
    /// Download priority: 0 = low, 1 = normal, 2 = high
    pub(super) priority: u32,
}

/// Pending `find_sources`/`find_notes` IPC response channel, paired with the
/// caller-generated `request_id` so `NetworkCommand::CancelSearch` can find
/// and tear down the underlying KAD search if the IPC caller times out.
pub(super) type PendingHelperSearchTx<T> = (u64, oneshot::Sender<T>);

/// Source record held until the named buddy ACKs `PROXY_STORE`, so overlay
/// `FIND_VALUE` cannot advertise a buddy that cannot bounce `CALLBACK_REQ`.
pub(super) struct EmberPendingProxyOverlay {
    pub(super) record: ember::dht::publish::SignedRecord,
    pub(super) reference: EmberRecordRef,
    pub(super) queued_at: std::time::Instant,
}

pub(super) const EMBER_PROXY_OVERLAY_TTL: std::time::Duration = std::time::Duration::from_secs(90);
pub(super) const MAX_EMBER_PENDING_PROXY_OVERLAY: usize = 256;

pub(super) struct NetworkState {
    pub(super) local_id: KadId,
    pub(super) user_hash: [u8; 16],
    pub(super) routing_table: RoutingTable,
    pub(super) search_manager: SearchManager,
    pub(super) publish_manager: PublishManager,
    pub(super) dht_store: DhtStore,
    pub(super) stats: NetworkStats,
    pub(super) pending_keyword_searches: HashMap<SearchId, PendingKeywordSearch>,
    /// Pending server TCP search: when we send OP_SEARCHREQUEST, store the results here
    /// until poll_messages() delivers OP_SEARCHRESULT.
    pub(super) pending_server_search: Option<PendingServerSearch>,
    pub(super) active_search_request: Option<ActiveSearchRequest>,
    /// eMule OP_QUERY_MORE_RESULT: capped follow-up requests for more server results.
    pub(super) server_search_more_needed: bool,
    pub(super) server_search_more_requests: u8,
    /// A second TCP search to send this server once the current one finishes,
    /// as `(request_id, wire expression)`. A related search has two different
    /// questions for the one connected server — the keyword query the user can
    /// see, and eMule's co-share request for the seed hashes — and a
    /// connection carries one search at a time. Lives here beside
    /// `server_search_more_needed` because it is sent from the same place, by
    /// the same rule: queue it in the poll loop, send it on the next pass.
    pub(super) server_followup_search: Option<(u64, Vec<u8>)>,
    /// Counter for throttling server keep-alive (sent every N poll ticks)
    pub(super) server_poll_count: u32,
    /// Counter for pending server search timeout (in poll ticks)
    pub(super) server_search_age: u32,
    /// Counter for pending server UDP search timeout (in poll ticks)
    pub(super) server_udp_search_age: u32,
    /// Throttled UDP global search queue: packets to send one-at-a-time at
    /// 750ms intervals (eMule UDPSEARCHSPEED = SEC2MS(3)/4).
    ///
    /// Each entry carries the `request_id` it was queued for. The queue drains
    /// over minutes at that rate, so "the search this belongs to is whatever is
    /// active when the packet finally goes out" is only true for as long as
    /// every teardown path remembers to clear it — and a server's reply is
    /// admitted on the strength of its IP being in `udp_search_sent_ips`, so
    /// getting that wrong puts answers to the previous query into the current
    /// tab. Carrying the id makes it a property of the packet instead.
    pub(super) udp_search_queue: VecDeque<(u64, Vec<u8>, std::net::SocketAddr)>,
    /// Source searches tied to pending downloads (search_id -> (transfer_id, file_hash_md4)).
    /// File hash is carried alongside so the search-completion handler can build
    /// CallbackReqs / inject sources without re-reading `pending_downloads`, which
    /// gets consumed the moment `try_start_from_known` promotes a transfer to
    /// active (server returned sources first).
    pub(super) download_source_searches: HashMap<SearchId, (String, [u8; 16])>,
    /// Per-source-search cursor of how many of `search.results` have already
    /// been streamed into the download (search_id -> processed result count).
    /// KAD source searches stay alive for ~60s collecting results; rather than
    /// dumping everything into the download only at completion (which left a
    /// download visibly starved for up to a minute even when KAD answered
    /// within seconds), the `search_poll_timer` tick streams freshly-arrived
    /// reachable sources incrementally — eMule's `CSearch::ProcessResult`
    /// hands each source to the download the moment a node answers. Entries
    /// are pruned when their search leaves `download_source_searches`.
    pub(super) source_search_stream_cursor: HashMap<SearchId, usize>,
    /// Direct sources a KAD source search found before capacity eviction ended
    /// it: `(file_hash, ip, tcp_port, udp_port, user_hash, connect_options)`.
    /// The eviction path injects them into the download at once but cannot
    /// reach the source manager, so they are recorded as KAD finds on the next
    /// search-poll tick instead of reaching the Origin column unlabelled.
    pub(super) evicted_kad_sources: Vec<([u8; 16], Ipv4Addr, u16, u16, [u8; 16], u8)>,
    /// Downloads waiting for sources (transfer_id -> PendingDownload)
    pub(super) pending_downloads: HashMap<String, PendingDownload>,
    pub(super) data_dir: PathBuf,
    /// Serializes every known.met writer, including shutdown, so a timed-out
    /// periodic snapshot cannot rename over a newer authoritative save.
    pub(super) known_met_save_lock: Arc<tokio::sync::Mutex<()>>,
    /// Monotonic generation for async `server.met` writes (latest wins).
    pub(super) server_met_save_generation: Arc<std::sync::atomic::AtomicU64>,
    /// Serializes async `server.met` writers so a superseded snapshot cannot
    /// finish after a newer one and clobber it (generation check under lock).
    pub(super) server_met_save_lock: Arc<std::sync::Mutex<()>>,
    /// Same ownership rule for periodic/disconnect/shutdown nodes.dat writes.
    pub(super) nodes_save_lock: Arc<tokio::sync::Mutex<()>>,
    /// The same rule for `nodes_ember.dat`, on its own lock: the periodic write
    /// is spawned from the arm that has just handed `nodes_save_lock` to the
    /// nodes.dat task, so sharing one would either stall the event loop or skip
    /// the ember save every tick.
    pub(super) ember_nodes_save_lock: Arc<tokio::sync::Mutex<()>>,
    pub(super) external_ip: Option<Ipv4Addr>,
    pub(super) external_udp_port: Option<u16>,
    /// STUN-over-TCP-confirmed public TCP port (probe from the listen port),
    /// once stability-confirmed by `apply_tcp_mapping_keepalive`. `None` when
    /// unconfirmed or STUN keep-alive is off/suspended — advertising then
    /// falls back to the configured listener port.
    pub(super) external_tcp_port: Option<u16>,
    /// `Some(port)` while UPnP holds a live inbound TCP forward. Outranks
    /// `external_tcp_port` in `advertised_tcp_port` — see that function.
    pub(super) upnp_tcp_port: Option<u16>,
    /// Live Hello / publish TCP port (updated by mapping keep-alive).
    pub(super) advertise_tcp_port: Arc<std::sync::atomic::AtomicU16>,
    /// Live Hello / publish UDP port (updated by mapping keep-alive).
    pub(super) advertise_udp_port: Arc<std::sync::atomic::AtomicU16>,
    pub(super) stun_keepalive_enabled: bool,
    /// Session auto-suspend when NAT is symmetric/open/unstable (Settings ports win).
    pub(super) stun_ka_auto_suspended: bool,
    /// When auto-suspend started (for periodic retry).
    pub(super) stun_ka_suspended_at: Option<std::time::Instant>,
    /// Last STUN-observed public UDP port awaiting stability confirmation.
    pub(super) stun_ka_candidate_port: Option<u16>,
    /// Consecutive identical candidate observations (need 2 before advertise).
    pub(super) stun_ka_stable_hits: u8,
    /// Same stability tracking as `stun_ka_candidate_port` /
    /// `stun_ka_stable_hits`, but for STUN over TCP. Kept separate because
    /// TCP and UDP NAT mappings are independent.
    pub(super) stun_ka_tcp_candidate_port: Option<u16>,
    pub(super) stun_ka_tcp_stable_hits: u8,
    /// Public UDP port last stably advertised by STUN keep-alive (if any).
    /// Used so revert/firewall recheck do not wipe peer-voted ports.
    pub(super) stun_sourced_udp_port: Option<u16>,
    pub(super) firewalled: bool,
    pub(super) firewall_checks_sent: u32,
    pub(super) peer_nicknames: HashMap<KadId, String>,
    /// Outstanding publish requests awaiting `PublishRes` acks.
    ///
    /// Keyed by `(target_hash, peer_addr)` so each publish-to-peer
    /// pair is tracked individually — this lets the ack counter count
    /// *every* successful delivery instead of collapsing to one per
    /// target (fixes the long-standing 0-confirmed publish cycle bug
    /// where many peers acked but we silently dropped all but the first).
    /// Value carries the original file hash/target (for retry book-keeping),
    /// the latest send timestamp (for stale cleanup), whether this is a source
    /// publish (vs keyword/notes), and how many publish packets are pending for
    /// this `(target, peer)` pair. The count matters for eMule-style keyword
    /// batches split into multiple `PublishKeyReq` packets with the same target.
    pub(super) publish_pending: HashMap<(KadId, SocketAddr), (KadId, i64, bool, u32)>,
    pub(super) publish_confirmed: u32,
    /// Diagnostic counters for `PublishRes` packet accounting. These let
    /// the `Publish cycle:` log line surface exactly where packets are
    /// being dropped. Seen from newest (closest to the "packet leaves the
    /// wire") to oldest (closest to the handler):
    ///
    /// - `publish_res_plain_seen`: raw inbound with `data[0]==0xE4 &&
    ///   data[1]==0x4B`, counted **before** IP filter / rate limit /
    ///   decompress / decrypt. Obfuscated responses look like ciphertext
    ///   at byte 0 and are *not* counted here (they can't be — byte 1 is
    ///   random). Use this to tell whether plain PublishRes even reach
    ///   our socket.
    /// - `publish_res_obf_decoded`: obfuscated UDP packets that
    ///   successfully decrypt **and** decode as a `PublishRes`. Pairs
    ///   with `obf_decoded_total` so you can see whether the drop is
    ///   specific to PublishRes or general to our decrypt path.
    /// - `obf_decoded_total`: any obfuscated UDP packet that decrypted
    ///   and decoded. Baseline for the previous counter.
    /// - `publish_res_wire`: `PublishRes` reached the decoded-message
    ///   stage (plain or obfuscated), before `validate_response`.
    /// - `publish_res_received`: handler entered, any load value.
    /// - `publish_res_unmatched`: decoded but `validate_response` said
    ///   unsolicited, OR handler couldn't match `publish_pending`.
    pub(super) publish_res_plain_seen: u64,
    pub(super) publish_res_obf_decoded: u64,
    pub(super) obf_decoded_total: u64,
    pub(super) publish_res_wire: u64,
    pub(super) publish_res_received: u64,
    pub(super) publish_res_unmatched: u64,
    /// Per-file count of KAD peers that acknowledged the most recent source
    /// publish cycle with a `PublishRes`. Used as a crude "complete sources"
    /// estimate for files the user is purely sharing (where SourceManager
    /// has no entries because we never searched/downloaded them).
    /// Reset to 0 at the start of each source-publish cycle.
    pub(super) source_publish_acks: HashMap<KadId, u32>,
    /// Store-keyword searches: search_id -> keyword-centric publish batch.
    pub(super) store_keyword_searches: HashMap<SearchId, KeywordPublishBatch>,
    /// Store-source searches: search_id -> (file_hash, publish message)
    pub(super) store_source_searches: HashMap<SearchId, (KadId, KadMessage)>,
    /// Pending notes searches: search_id -> (request_id, response sender).
    /// `request_id` (caller-generated) lets `NetworkCommand::CancelSearch`
    /// cancel a `find_notes` call on IPC timeout, same as it already does for
    /// `search_files`'s keyword searches.
    pub(super) pending_notes_searches:
        HashMap<SearchId, PendingHelperSearchTx<Result<Vec<SearchResult>, String>>>,
    /// Pending note publishes, including the exact StorePacket payload used by
    /// both eager lookup sends and completion mop-up.
    pub(super) pending_note_publishes: HashMap<SearchId, PendingNotePublish>,
    /// Notes we have published to the KAD DHT, keyed by the file's KadId.
    /// Re-published periodically so our comments/ratings don't expire from
    /// the network after ~24h; loaded from the `published_notes` table at
    /// startup so republishing survives restarts.
    pub(super) published_notes: HashMap<KadId, PublishedNote>,
    /// eMule `CSharedFileList::m_currFileNotes`: round-robin cursor over
    /// `published_notes`, mirroring `PublishManager::source_cursor` (see
    /// `round_robin_next`) since notes live outside `PublishManager`.
    pub(super) notes_publish_cursor: Option<KadId>,
    /// Nodes that reported load=100 -- avoid publishing to them for a while
    pub(super) overloaded_nodes: HashMap<Ipv4Addr, i64>,
    pub(super) flood_protection: FloodProtection,
    /// Pending Kad <7 (and crypt-off) Hello verification challenges.
    pub(super) legacy_challenges: LegacyChallengeTracker,
    pub(super) buddy_manager: BuddyManager,
    /// Our UDP verification key seed (random, stable for session)
    pub(super) udp_key_seed: u32,
    pub(super) tcp_port: u16,
    pub(super) udp_port: u16,
    /// Actual UDP port the QUIC broker endpoint bound to. `None` until
    /// the broker is initialised, then set to the real `local_addr()`
    /// port — which may differ from `tcp_port` if the requested port
    /// was already in use (e.g. when `tcp_port == udp_port` and the Kad
    /// UDP socket got there first). Anything that advertises our QUIC
    /// reachability (rendezvous registration / heartbeat) must read
    /// from here, not from `settings.tcp_port`.
    pub(super) quic_port: Option<u16>,
    /// Public UDP port of the QUIC socket, discovered by a STUN transaction
    /// run on that socket before quinn took ownership of it. `None` when the
    /// probe found nothing, in which case `quic_port` is the best guess.
    ///
    /// Separate from `quic_port` because a re-mapping NAT gives them different
    /// values, and every consumer wants one specific side of that: UPnP maps
    /// the *bound* port, while anything a peer dials needs the *public* one
    /// (read it through `advertised_quic_port`). Mapping keep-alive holds the
    /// mapping open but cannot re-read this port: quinn never surfaces
    /// non-QUIC datagrams.
    pub(super) quic_public_port: Option<u16>,
    pub(super) upnp_mapped: bool,
    /// IP filter for blocking known-bad ranges (eMule ipfilter.dat compatible)
    pub(super) ip_filter: IpFilter,
    /// Cached set of banned peer IPs for fast lookup at network level
    pub(super) banned_ips: HashSet<Ipv4Addr>,
    /// Whether to use protocol obfuscation (RC4 encryption) for outgoing KAD packets
    pub(super) obfuscation_enabled: bool,
    /// Shared firewall status that can be updated from spawned tasks
    pub(super) firewalled_shared: Arc<std::sync::atomic::AtomicBool>,
    /// Set by the upload listener when a KAD firewall-probe IP connects
    /// back. Consumed by the network loop to call `handle_tcp_connect_back`
    /// without conflating real proof with UPnP clearing `firewalled_shared`.
    pub(super) tcp_connect_back_shared: Arc<std::sync::atomic::AtomicBool>,
    /// Shared external IPv4 encoded as a little-endian u32 — the same
    /// layout ed2k uses for a HighID `client_id` on the wire.
    /// `0` means unknown (no trusted source has reported our public IP yet);
    /// any non-zero value is our public IPv4 confirmed by a trusted source
    /// (ed2k server HighID, multi-reporter KAD consensus, or UPnP→firewall
    /// re-verification). The upload listener reads this atomic when building
    /// an outgoing `OP_HELLOANSWER`: advertising our real ID here instead
    /// of a hardcoded `0` lets strict eMule forks and older clients
    /// correctly treat us as HighID in their queue scoring and callback
    /// logic, rather than relying on BaseClient.cpp's forgiving
    /// `m_nUserIDHybrid == 0 → use connect IP` auto-heal. Keeps this in
    /// sync with `external_ip` via `set_external_ip` below so there is no
    /// way to update one without the other.
    pub(super) external_ip_shared: Arc<std::sync::atomic::AtomicU32>,
    /// Whether we've done the initial self-lookup (FindNode for own ID)
    pub(super) self_lookup_done: bool,
    /// Timestamp of last self-lookup (eMule repeats every 4 hours)
    pub(super) last_self_lookup: i64,
    /// When the KAD stack was started (eMule: first self FindNode after MIN2S(3))
    pub(super) kad_started_at: i64,
    /// eMule `CPrefs::m_tLastContact` — updated on each accepted incoming KAD UDP packet.
    pub(super) last_kad_contact: Option<i64>,
    /// Whether UDP is firewalled (separate from TCP, like eMule)
    pub(super) udp_firewalled: bool,
    /// Whether UDP firewall status has been verified
    pub(super) udp_fw_verified: bool,
    /// Whether the initial post-bootstrap publish has been done
    pub(super) first_publish_done: bool,
    /// Whether the initial KAD source search burst for pending downloads has been done
    pub(super) kad_initial_source_burst_done: bool,
    /// Whether the immediate friend presence publish has fired after IP discovery
    pub(super) friend_presence_initial_done: bool,
    /// ed2k server list
    pub(super) server_list: ServerList,
    /// Whether we're connected to an ed2k server
    pub(super) server_connected: bool,
    /// Active ed2k server connection (kept for keep-alive and source requests)
    pub(super) server_connection: Option<Ed2kServerConnection>,
    /// Address of the currently connected server
    pub(super) server_addr: Option<SocketAddr>,
    /// Throttled UDP source-request queue: packets paced at ~1 per second
    /// (eMule sends one per ~1s during its global sweep).
    pub(super) udp_source_queue: VecDeque<(Vec<u8>, std::net::SocketAddr)>,
    /// Last UDP source request per `(server_ip, server_tcp_port, file_hash)`.
    /// Enforces eMule's 30-minute UDP source reask cadence per server/file.
    pub(super) server_udp_source_reask_at: HashMap<(String, u16, [u8; 16]), i64>,
    /// Pending client UDP OP_REASKFILEPING context. OP_REASKACK carries no
    /// file hash, so correlate by sender endpoint to update only one file list.
    /// Value is `(file_hash, sent_at)` — the timestamp lets the cap-eviction
    /// pass below drop the oldest (most likely dead/unreachable) entries
    /// instead of nuking every in-flight reask whenever the table fills up.
    pub(super) pending_udp_reasks: HashMap<(Ipv4Addr, u16), ([u8; 16], i64)>,
    /// Order-independent fingerprint `(entry_count, xor_fold)` of the last
    /// `OP_OFFERFILES` list actually sent from the `SharedFilesChanged`
    /// handler, so a re-fire whose offer set is byte-for-byte identical to
    /// what the server already has can skip re-sending it. Without this,
    /// a long AICH-only re-hash pass — which fires `SharedFilesChanged`
    /// every ~30s purely to checkpoint `known.met`, without actually
    /// adding/removing/completing any shared file — rebuilds and
    /// re-transmits the *entire* offer list to the server every single
    /// time even though nothing the server cares about changed. `None`
    /// until the first send this session, so the first `SharedFilesChanged`
    /// after connecting always sends unconditionally.
    pub(super) last_offer_files_signature: Option<(usize, u64)>,
    /// Set by SharedFilesChangedAck; main loop builds/queues chunked OP_OFFERFILES.
    pub(super) request_offer_files: bool,
    /// Hashes successfully included in an `OP_OFFERFILES` this server session.
    /// Drives the Library eD2K "published" badge (connection alone is not enough).
    pub(super) offered_ed2k_hashes: HashSet<[u8; 16]>,
    /// Round-robin cursor for TCP OP_GETSOURCES batching across downloads.
    pub(super) server_tcp_getsources_cursor: usize,
    /// Earliest unix-second at which another TCP `OP_GETSOURCES` frame may go
    /// out, shared by every path that sends one. eMule's `m_dwNextTCPSrcReq`;
    /// see `SERVER_TCP_SRCREQ_INTERVAL_SECS` for the server-credit accounting
    /// this protects. 0 means "may send now".
    pub(super) server_tcp_srcreq_next_at: i64,
    /// Unix-seconds timestamp of the most recent successful server login.
    /// Server source requests (OP_GETSOURCES) are held off until the
    /// connection has settled for `SERVER_SOURCE_SETTLE_SECS` so we don't
    /// blast a burst at the server before it has finished its post-login
    /// welcome sequence (OP_SERVERSTATUS / message / list / ident). eMule
    /// likewise paces source requests from its periodic ProcessLocalRequests
    /// loop rather than firing them the instant OP_IDCHANGE arrives; sending
    /// too early risks the server's flood protection silently dropping the
    /// request (and, on some servers, the rest of the session's source
    /// replies). 0 means "no server connected".
    pub(super) server_connected_at: i64,
    /// Per-file (hash hex) timestamp of the last *starved* fast re-ask of the
    /// connected server for sources. eMule keeps pulling the connected
    /// server's (growing) source list for a download that has no working
    /// sources; our normal batch is every 4 min, far too slow to recover
    /// when the initial source set is dead. This map throttles the fast
    /// re-ask to a flood-safe per-file interval (see
    /// `STARVED_SERVER_REASK_SECS`).
    pub(super) starved_server_reask_at: std::collections::HashMap<String, i64>,
    /// Round-robin cursor for fair KAD search slot distribution across downloads.
    pub(super) kad_source_search_cursor: usize,
    /// Dead source tracking (prevents reconnecting to failing sources)
    pub(super) dead_sources: DeadSourceList,
    /// Tracks which IP sent each byte range for corruption blame attribution
    pub(super) corruption_blackbox: CorruptionBlackBox,
    /// Pending AICH recovery retries: (file_hash, part_index) -> (failed_ips, retry_count)
    pub(super) aich_recovery_pending: ed2k::transfer::SharedAichPending,
    /// eMule-style persistent source lists per download (survives connection failures)
    pub(super) per_file_sources: HashMap<String, ed2k::sources::PerFileSourceList>,
    /// KAD search state for active downloads not in pending_downloads.
    /// Tracks (last_kad_search_at, search_count) so we periodically search
    /// for additional sources via KAD even while the download is running.
    pub(super) active_kad_search_state: HashMap<String, (i64, u32)>,
    /// Senders for injecting new sources into active multi-source downloads
    pub(super) active_source_senders: HashMap<String, mpsc::Sender<DownloadSource>>,
    /// UDP source-discovery diagnostic counters. Surfaced in the
    /// periodic discovery health log so the user can verify UDP
    /// source-asking is actually flowing (vs silently broken by
    /// firewall, missing obfuscation, dead servers, etc.). All four
    /// are monotonic since process start; the health log prints
    /// deltas. Saturating arithmetic so a long-running session can't
    /// overflow `u64`.
    pub(super) udp_discovery_sent: u64,
    pub(super) udp_discovery_send_errs: u64,
    pub(super) udp_discovery_replies: u64,
    pub(super) udp_discovery_sources_found: u64,
    /// Senders for injecting *pre-handshaked* peer streams into active
    /// multi-source downloads. Distinct from `active_source_senders`
    /// because the payload (`EstablishedSource`) carries an
    /// already-adopted reader/writer pair — used by the LowID-callback
    /// fast path to avoid the wasted-redial bug where we'd otherwise
    /// metadata-inject the peer and then try a fresh outbound connect
    /// to a NAT'd address. Mirrors `active_source_senders` in
    /// lifecycle: created at MultiSourceDownload construction, removed
    /// when the download completes / fails / is cancelled. Always
    /// registered/removed in lockstep with `active_source_senders` so
    /// neither leaks past the other.
    pub(super) active_established_senders:
        HashMap<String, mpsc::Sender<ed2k::multi_source::EstablishedSource>>,
    /// Overflow queue for sources discovered faster than the active download can accept them
    pub(super) active_source_overflow: HashMap<String, VecDeque<DownloadSource>>,
    /// Transfers started from a friend's file listing, mapped to that friend's
    /// Ember hash. Seeded by `StartDownload` only after the caller-supplied
    /// hash is checked against live friend membership, so this is always a
    /// friend we actually have.
    ///
    /// Lets a failed dial to that friend escalate to `OP_EMBER_XFER_REQ`
    /// instead of parking the source as dead: a friend behind NAT is
    /// unreachable by dialing but perfectly able to dial *us*, and unlike the
    /// eD2K/KAD callback paths that fallback needs neither a server login nor
    /// a HighID.
    pub(super) transfer_friend_hint: HashMap<String, [u8; 16]>,
    /// In-flight friend transfer requests, keyed by `(friend, file hash)`.
    /// Bounds retries and lets an `OP_EMBER_XFER_ACK` be matched to the
    /// request it answers.
    pub(super) friend_xfer_attempts: HashMap<([u8; 16], [u8; 16]), FriendXferAttempt>,
    /// When we last accepted an inbound `OP_EMBER_XFER_REQ` from each friend.
    /// A friend session is authenticated, so this is not an anti-spoofing
    /// measure — it just stops a buggy or malicious *friend* from using us as
    /// a dialer at an unbounded rate.
    pub(super) friend_xfer_inbound_last: HashMap<[u8; 16], std::time::Instant>,
    /// Session counters for friend transfer negotiation, surfaced through
    /// `get_ember_diagnostics`.
    pub(super) friend_xfer_stats: FriendXferStats,
    /// Friends whose [`ed2k::messages::EmberXferMethod::Punch`] request we
    /// accepted, mapped to when we accepted it.
    ///
    /// Read by the punch responder to decide that an arriving punch from this
    /// friend must take the eD2K *serve* role rather than the default inbound
    /// role — the friend is the downloader and is waiting for our `OP_HELLO`.
    /// Entries are short-lived: they only need to outlive the rendezvous punch
    /// TTL, and a stale one would wrongly make a later *social* punch from the
    /// same friend take the serve role.
    pub(super) friend_xfer_punch_serve: HashMap<[u8; 16], std::time::Instant>,
    /// JoinHandles for spawned download tasks, keyed by transfer_id
    pub(super) download_handles: HashMap<String, tokio::task::JoinHandle<()>>,
    /// Comment/rating manager
    pub(super) comment_manager: Arc<RwLock<CommentManager>>,
    pub(super) firewall_checker: FirewallChecker,
    /// eMule `CUDPFirewallTester::m_liPossibleTestClients`: fresh contacts
    /// (discovered via the crippled NODEFWCHECKUDP-style lookup below and kept
    /// OUT of the routing table) that we have never sent a UDP packet to, used
    /// as UDP-firewall probe targets. Drawing probe targets from already-known
    /// routing-table peers can yield a false "UDP open" verdict behind a
    /// restricted-cone NAT, so probes must go to genuinely fresh IPs.
    pub(super) udp_fw_candidate_pool: VecDeque<KadContact>,
    /// The in-flight fresh-node lookup seeding `udp_fw_candidate_pool`
    /// (eMule `CSearchManager::FindNodeFWCheckUDP`). Tracked so we don't start
    /// duplicate lookups while one is still gathering candidates.
    pub(super) udp_fw_node_search: Option<SearchId>,
    /// Whether we have LowID from the server
    pub(super) low_id: bool,
    /// Our server-assigned client ID
    pub(super) server_client_id: u32,
    /// The TCP port we advertised in `OP_LOGINREQUEST` for the current
    /// session. eD2k has no "update my port" message once logged in — the
    /// server only learns a new port by us reconnecting — so this lets the
    /// mapping keep-alive notice a STUN-confirmed remap that arrived *after*
    /// login and trigger a reconnect while still LowID (see the
    /// `tcp_map_ka_result_rx` arm). `None` while disconnected; irrelevant
    /// then since the reconnect check is gated on `server_connected`.
    pub(super) server_login_tcp_port: Option<u16>,
    /// Last time the mapping keep-alive triggered a reconnect to push a
    /// newly confirmed TCP port to the server (see `tcp_map_ka_result_rx`).
    /// A per-value cooldown already falls out of the two-hit confirmation
    /// gate (`tcp_port_confirmation`), but this adds an explicit floor so a
    /// pathologically unstable mapping (a "confirmed" port that keeps
    /// changing every couple of cycles) can't reconnect-thrash the server
    /// session.
    pub(super) last_tcp_remap_reconnect_at: Option<std::time::Instant>,
    /// Background server connection task (non-blocking)
    pub(super) pending_server_connect: Option<tokio::task::JoinHandle<ServerConnectResult>>,
    /// Shared set of user hashes expected as incoming buddy connections (checked by upload listener)
    pub(super) pending_buddy_hashes: PendingBuddySet,
    /// Shared buddy info for Hello tags (updated when buddy connects/disconnects)
    pub(super) shared_buddy_info: upload_server::SharedBuddyInfo,
    /// Shared IP filter snapshot for the upload handler
    pub(super) shared_ip_filter: kad::ip_filter::SharedIpFilter,
    /// Lock-free KAD upload wire bytes (drained into StatsManager each second)
    pub(super) kad_upload_overhead: crate::storage::statistics::SharedKadUploadOverhead,
    /// Ember Peer Exchange wire bytes (TCP EPX + Ember UDP Exchange*).
    /// Same Arc as `StatsManager::epx_counters`.
    pub(super) epx_overhead: crate::storage::statistics::SharedSxOverheadCounters,
    /// Ember DHT (and Ember-native handshake / transport ping) wire bytes.
    /// Same Arc as `StatsManager::ember_dht_counters`.
    pub(super) ember_dht_overhead: crate::storage::statistics::SharedSxOverheadCounters,
    /// Event receiver for our buddy connection (we are firewalled)
    pub(super) buddy_event_rx: Option<mpsc::Receiver<BuddyEvent>>,
    /// Event receiver for the client we're serving as buddy for
    pub(super) serving_event_rx: Option<mpsc::Receiver<BuddyEvent>>,
    /// Background buddy outgoing connect+handshake task.
    pub(super) pending_outgoing_buddy:
        Option<tokio::task::JoinHandle<Option<kad::buddy::OutgoingBuddyConnection>>>,
    /// Whether the server auto-reconnect loop is allowed to run.
    /// Starts from settings; enabled on manual connect, disabled on manual disconnect
    /// or after auto-connect gives up on the preferred server.
    pub(super) server_auto_reconnect: bool,
    /// Consecutive preferred-server connection failures for exponential backoff
    /// (reset on success). After [`AUTO_CONNECT_MAX_FAILURES`], auto-reconnect stops.
    pub(super) server_reconnect_failures: u32,
    /// Only server auto-reconnect / auto-connect may dial. Set on connect and
    /// persisted as last successful server on login.
    pub(super) preferred_ed2k_server: Option<(String, u16)>,
    /// Instant when the last server connect attempt was started
    pub(super) server_last_connect_attempt: Option<std::time::Instant>,
    /// Pending USS ping timestamps for RTT measurement (at most one in flight).
    pub(super) pending_uss_pings: HashMap<SocketAddr, std::time::Instant>,
    /// Currently selected USS ping target
    pub(super) uss_host: Option<(SocketAddr, KadId)>,
    /// Last USS host — excluded on the next selection so rotation cannot
    /// immediately re-pick the same unresponsive contact.
    pub(super) uss_prev_host: Option<SocketAddr>,
    /// Consecutive *timed-out* USS pings (rotate host after 3)
    pub(super) uss_missed_pongs: u32,
    /// When the current USS host was selected
    pub(super) uss_host_selected_at: i64,
    /// Shared RTT queue for feeding latency samples to the limiter loop
    pub(super) uss_rtt_queue: crate::bandwidth::UssRttQueue,
    /// Shared USS enabled flag
    pub(super) uss_enabled_flag: crate::bandwidth::UssEnabledFlag,
    /// AICH recovery sets computed this session and not yet appended to
    /// `known2_64.met`. The file is indexed and read by `ed2k::aich::Known2Store`,
    /// never held in memory; only this queue is.
    pub(super) pending_known2_sets: Vec<ed2k::aich::AICHRecoveryHashSet>,
    /// Shared max upload slots (updated on settings change, read by upload handler)
    pub(super) upload_max_slots: Arc<std::sync::atomic::AtomicUsize>,
    /// Shared obfuscation flag mirroring `state.obfuscation_enabled`. The
    /// upload listener captures this `Arc` at spawn time and reads it on
    /// every Hello / EmuleInfo build, so toggling obfuscation in
    /// Settings hot-reloads inbound advertised crypt support to match
    /// the outbound paths (which use `state.obfuscation_enabled`
    /// directly). Without this, inbound and outbound diverge until
    /// restart.
    pub(super) obfuscation_enabled_shared: Arc<std::sync::atomic::AtomicBool>,
    /// Shared "skip video compression" flag for the upload sender loop.
    pub(super) skip_compress_video_shared: Arc<std::sync::atomic::AtomicBool>,
    /// Shared "filter incoming connections via IP filter" flag for the
    /// TCP accept loop.
    pub(super) filter_incoming_shared: Arc<std::sync::atomic::AtomicBool>,
    /// Shared "answer vanilla OP_ASKSHAREDFILES browse requests" flag for
    /// the upload listener. Mirrors `settings.allow_shared_files_browse`.
    pub(super) share_browsing_shared: Arc<std::sync::atomic::AtomicBool>,
    /// Whether the EPX payload needs rebuilding (set on source changes, cleared after rebuild)
    pub(super) ember_payload_dirty: bool,
    /// The same EPX payload packed to fit one Ember UDP datagram.
    ///
    /// Built from the same entries as `shared_ember_payload` on each rebuild,
    /// because the TCP payload it parallels is sized for a stream and cannot
    /// be sent as a datagram — see [`ember::MAX_EPX_UDP_PAYLOAD`]. Kept on
    /// `NetworkState` rather than behind an `Arc<RwLock<_>>` like its TCP
    /// counterpart because only the network task's UDP handler reads it; the
    /// TCP one is shared with every spawned transfer task.
    pub(super) ember_udp_payload: Arc<Vec<u8>>,
    /// Known Ember peer addresses for peer discovery mesh building.
    /// Value is the last time we saw this peer (either by direct connect or
    /// via EPX from another peer). Stale entries are pruned by
    /// `prune_stale_ember_peers` against `KNOWN_EMBER_PEER_TTL` and the
    /// total set is capped at `MAX_KNOWN_EMBER_PEERS` to prevent unbounded
    /// growth on long-running sessions. The wire cap is much smaller
    /// (`ember::MAX_EPX_PEERS = 50`); the in-memory headroom exists so we
    /// can rotate which subset gets advertised across rebuilds.
    pub(super) known_ember_peers: HashMap<(Ipv4Addr, u16), std::time::Instant>,
    /// `(ip, port) -> (noise_pub, last_seen)` cache populated from KAD
    /// source publishes that carry `kad::publish::EMBER_NOISE_PUB_TAG`.
    /// Lets `ember_ping_peer` (and future Ember-native callers) dial a
    /// peer's Noise transport without copying hex pubkeys around.
    /// Bounded by `MAX_KNOWN_EMBER_NOISE_KEYS` and pruned by
    /// `KNOWN_EMBER_PEER_TTL` so a long session can't unboundedly
    /// retain stale keys for peers that have rotated.
    pub(super) ember_noise_keys: HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)>,
    /// `(ip, udp_port)` of Ember peers met over an eD2K client-to-client
    /// session (capability bit plus a verified `ember_hash` binding) for whom
    /// we hold no Noise static key — the key only ever arrives on a KAD
    /// `ember_npub` tag, and this peer was reached through a server-sourced
    /// download or upload instead.
    ///
    /// They are still dialable: `EmberTransport::prepare_outgoing` falls back
    /// to Noise_XX when no static key is supplied, costing one extra round
    /// trip. That is what lets a KAD-less client still join the DHT. Keyed by
    /// UDP port because the Noise transport rides the shared KAD UDP socket.
    /// Bounded and pruned exactly like `known_ember_peers`.
    pub(super) ember_keyless_peers: HashMap<(Ipv4Addr, u16), std::time::Instant>,
    /// Signed DHT identity of an eD2K-session Ember peer. Kept even when the
    /// routing table refuses the address (LAN / `block_private_ips`) so
    /// FIND_VALUE can still ask a connected publisher. Retained while the
    /// contact's own `last_seen` is inside `KNOWN_EMBER_PEER_TTL` — a peer that
    /// keeps sending signed frames renews its entry without needing a fresh
    /// eD2K introduction.
    pub(super) ember_session_dht_contacts: HashMap<(Ipv4Addr, u16), ember::dht::EmberContact>,
    /// Every Ember peer we remember, across restarts — the thing
    /// `nodes_ember.dat` actually holds.
    ///
    /// Deliberately not the routing table. The table is live state: a lead that
    /// will not answer three pings has to lose its bucket slot, and a peer the
    /// public table refuses outright (LAN or CGNAT under `block_private_ips`)
    /// never gets one at all. Writing the file straight from the table made
    /// those two facts mean "forget this address", which cost a node most of
    /// its peers on every restart and could only ever shrink the file. See
    /// [`ember::dht::peer_cache`].
    pub(super) ember_bootstrap_cache: ember::dht::peer_cache::BootstrapCache,
    /// What this session knows about `nodes_ember.dat`. Lets the save path tell
    /// "the book is genuinely empty" from "we never got to look at it", and
    /// from "we read a truncated file and must not write our subset back over
    /// it" — see [`ember::dht::bootstrap::save_nodes`]. `Loaded` when the file
    /// is simply absent, which is a new profile rather than a failure.
    pub(super) ember_nodes_file: ember::dht::bootstrap::NodesFileState,
    /// Unix time of our last self-publish to the Ember rendezvous key, so it
    /// republishes on the same cadence as any other source record. 0 = never.
    pub(super) ember_rendezvous_published_at: i64,
    /// The in-flight rendezvous *lookup*, if any. Tracked separately from
    /// download and UI source searches so its results can be harvested for
    /// Noise keys and then discarded — nobody is waiting on them.
    pub(super) ember_rendezvous_search: Option<SearchId>,
    /// Unix time the last rendezvous lookup started, to space out retries
    /// while the routing table is still empty. 0 = never.
    pub(super) ember_rendezvous_looked_up_at: i64,
    /// Consecutive rendezvous lookups that converted nobody from the live
    /// table, driving the retry backoff. Reset when any listed peer is
    /// already a routing-table or session contact. A node holding 1–19
    /// contacts that include a listed peer therefore never escalates.
    pub(super) ember_rendezvous_empty_streak: u32,
    /// When each contact was last sent an `ANNOUNCE_PEER`, so gossip
    /// exchange rotates through the table instead of pinning itself to
    /// whichever peers answered most recently. Pruned against the live
    /// contact set alongside the staleness purge.
    pub(super) ember_announced_at: HashMap<ember::dht::EmberNodeId, i64>,
    /// Record keys still unplaced for each file being published. A file's
    /// republish schedule advances only when this empties, so a file is not
    /// retired while some of its keywords remain unsearchable.
    pub(super) ember_publish_unplaced: HashMap<([u8; 16], EmberPublishKind), HashSet<[u8; 16]>>,
    /// Consecutive publish rounds each file has left unconfirmed, driving the
    /// [`EMBER_PUBLISH_MAX_ATTEMPTS`] backoff.
    pub(super) ember_publish_attempts: HashMap<([u8; 16], EmberPublishKind), EmberPublishAttempts>,
    /// Bookkeeping for the publish heartbeat, accumulated by the selection and
    /// flush paths and reset each time it logs.
    pub(super) ember_publish_pass: EmberPublishPassStats,
    /// Batched publish queue: groups a tick's records by destination so a
    /// large library's republish fits the link and the peer rate limits.
    pub(super) ember_batch_publish: EmberBatchPublisher,
    /// Unix time the Ember DHT started, the reference for scheduling the
    /// first self-lookup and the fallback for disconnect detection before
    /// anything has been received.
    pub(super) ember_started_at: i64,
    /// Whether the join-time self-lookup has run yet. Cleared when the DHT
    /// looks disconnected so a recovering node repeats it.
    pub(super) ember_self_lookup_done: bool,
    /// Unix time of the last self-lookup, for the periodic repeat.
    pub(super) ember_last_self_lookup: i64,
    /// Unix time we last received any Ember DHT frame. `None` until the first
    /// one arrives. Drives disconnect detection.
    ///
    /// Only ever written when a frame actually arrives. The disconnect re-arm
    /// used to stamp it too, to keep itself from firing every tick, which made
    /// `ember_dht_seconds_since_inbound` read a couple of seconds on a node
    /// that had heard nothing for an hour — "joined and quiet" and "stuck
    /// rejoining" looked identical in diagnostics, and the second is the one
    /// worth seeing. The debounce lives in `ember_rearmed_at` instead.
    pub(super) ember_last_inbound: Option<i64>,
    /// Unix time the disconnect re-arm last fired, so it fires once per silent
    /// stretch rather than on every maintenance tick within one.
    pub(super) ember_rearmed_at: Option<i64>,
    /// Overlay contact count as of the previous maintenance tick, so emptying
    /// can re-arm bootstrap on the *transition* to zero rather than every tick
    /// spent there.
    pub(super) ember_last_overlay_contacts: usize,
    /// Unix time of the last empty-overlay re-arm. 0 = never. Floors how often
    /// that re-arm may fire so a node with no reachable peers cannot hammer
    /// the rendezvous lookup every eviction cycle.
    pub(super) ember_empty_rearmed_at: i64,
    /// Nodes a real lookup found to be closest to a record key, per key, with
    /// the unix time we learned them.
    ///
    /// Kademlia says to find the k closest nodes to a key and store there. Our
    /// own table cannot answer that question well for a distant key: bucket `b`
    /// holds twenty nodes drawn from a range of `2^b` addresses, so its
    /// "closest" are nowhere near the true closest, while a searcher's walk
    /// converges on exactly those. Publishing from the table alone therefore
    /// puts records slightly beside where lookups go looking, and further beside
    /// as the network grows. Storer-side replication drags them back over a few
    /// hours, so it self-heals rather than failing outright — but starting in
    /// the right place is cheaper than converging on it.
    /// Node IDs, deliberately, not whole contacts. An earlier version cached the
    /// `EmberContact` values a lookup returned, address and Noise key included,
    /// and nothing revalidated them before the send — so for the whole four-hour
    /// life of an entry a publish kept addressing peers the routing table had
    /// since evicted, faulted for missed pings, or dropped on an IP-filter
    /// reload. Since the schedule only advances on an ack, those records were
    /// then re-queued every tick for four hours. An ID has to be resolved through
    /// the table at send time, which drops anyone no longer admitted and always
    /// uses the address the table holds now.
    pub(super) ember_publish_targets: HashMap<[u8; 16], (Vec<ember::dht::EmberNodeId>, i64)>,
    /// Keys waiting for such a lookup, oldest first. Publishing never blocks on
    /// this: a key with no cached set publishes from the table now and gets a
    /// better set for its next republish.
    pub(super) ember_publish_target_queue: std::collections::VecDeque<[u8; 16]>,
    /// In-flight target lookups, search id to the key each is resolving.
    pub(super) ember_publish_target_lookups: HashMap<u32, [u8; 16]>,
    /// Whether this session managed to read `store_ember.dat` (or found there was
    /// none to read). Only the shutdown save consults it, to tell an empty store
    /// from a file it never got to open — see `bootstrap::save_store`.
    pub(super) ember_store_loaded: bool,
    /// First stranger address to reach us unsolicited since the last reset, and
    /// when. A second one, from a different host and inside
    /// [`EMBER_UDP_REACHABLE_TTL_SECS`] of it, is what actually concludes our UDP
    /// port is open — see the reachability rule in `handle_ember_dht_inbound`.
    ///
    /// Timestamped because the pair has to be corroboration rather than a
    /// coincidence: the rule exists precisely because the list of paths that dial
    /// peers we hold no contact for is known to be incomplete, so an unaged first
    /// witness plus one uncovered dial hours later would be enough to conclude a
    /// filtered port is open.
    pub(super) ember_reach_witness: Option<(IpAddr, i64)>,
    /// Unix time a peer we had never contacted reached us on our own UDP port,
    /// which is the only Ember-native evidence that the port is open to the
    /// internet. `None` until that happens.
    ///
    /// Reachability otherwise comes entirely from the eD2K/KAD side —
    /// `firewalled` from the server's connect-back or KAD's firewall check,
    /// `udp_firewalled` from KAD's UDP probe. Both start pessimistic and
    /// `udp_firewalled` is only ever cleared by a KAD result, so a node running
    /// Ember with KAD switched off could never learn it was reachable and
    /// advertised every source record as firewalled for the life of the
    /// process. That fails safe, but it routes connections through a relay that
    /// did not need one, and it hides exactly the open-port nodes that make the
    /// best relays for everyone else. See [`ember_udp_reachable`].
    pub(super) ember_udp_reachable_at: Option<i64>,
    /// The external address `ember_reach_witness` and `ember_udp_reachable_at`
    /// were earned under. The evidence is dropped when the address moves to a
    /// different one, not when it is merely unknown for a while: KAD
    /// disconnect clears the address until STUN reports the same one again.
    /// See [`reach_evidence_survives`].
    pub(super) ember_reach_external_ip: Option<Ipv4Addr>,
    /// When each peer's last browse of our shares was reported, so repeats
    /// inside the quiet window stay out of the log and off the screen. See
    /// [`shares_browse_is_new`].
    pub(super) shares_browsed_seen: HashMap<(SharesBrowser, bool), std::time::Instant>,
    /// KAD-bridge bootstrap bookkeeping (slice 13): when the bridge last
    /// DHT-pinged each KAD-learned Ember peer and how many of those pings have
    /// gone unanswered, so it moves through the `ember_noise_keys` cache
    /// instead of re-pinging the same freshest few every cycle, while still
    /// retrying a peer — after [`bridge_retry_after`], which lengthens with the
    /// count — so one lost ping isn't final. Cleared for a peer as soon as it
    /// sends us anything, so proven-reachable peers never carry a backoff.
    /// Only consulted while the table is still sparse.
    pub(super) ember_kad_bridge_attempted: HashMap<(Ipv4Addr, u16), (std::time::Instant, u32)>,

    /// When the 1 Hz cold-start bridge pass last ran, so it keeps its own
    /// spacing rather than inheriting the maintenance tick's per-cycle budget.
    /// See [`EMBER_BRIDGE_FAST_INTERVAL`].
    pub(super) ember_bridge_fast_at: Option<std::time::Instant>,

    /// Start of the current one-second gossip-probe window and how many probes
    /// it has spent, so a per-tick budget cannot be re-granted to every inbound
    /// frame. See `probe_ember_gossip_leads`.
    pub(super) ember_gossip_probe_window: (std::time::Instant, usize),

    /// Which peers' introductions have been worth probing. Decides how much of
    /// the gossip-probe budget one introducer may spend; see
    /// [`ember::dht::gossip`] for why it never refuses a contact outright and
    /// is not consulted while the table is starved.
    pub(super) ember_gossip_reputation: ember::dht::gossip::GossipReputation,

    /// When we last asked each friend for its Ember DHT contacts, and when we
    /// last answered that question for them. Kept apart so the two directions
    /// cannot throttle each other: a friend asking us on its own schedule says
    /// nothing about when we should next ask them.
    pub(super) ember_friend_contacts_asked: HashMap<[u8; 16], std::time::Instant>,
    pub(super) ember_friend_contacts_served: HashMap<[u8; 16], std::time::Instant>,

    /// Session store-ack/fail totals as of the previous Ember publish
    /// heartbeat, so that line can report a per-cycle delta next to the total
    /// instead of printing a lifetime counter among per-cycle ones.
    pub(super) ember_publish_beat_acked: u32,
    pub(super) ember_publish_beat_failed: u32,
    /// Per-peer rate limit for UDP EPX `ExchangeData` ingestion —
    /// `(accepted_count_in_window, window_start)`. Unlike TCP EPX, which
    /// resets `MAX_EPX_PACKETS_PER_CONNECTION` naturally when the TCP
    /// connection closes, an authenticated Noise_IK UDP session has no
    /// "connection" to bound the count, so a single IK-authenticated peer
    /// could otherwise send unlimited `ExchangeData` packets. Bounded by
    /// `MAX_EMBER_UDP_EPX_RATE_ENTRIES` with LRU-by-window-start eviction,
    /// mirroring `known_ember_peers`.
    pub(super) ember_udp_epx_rate: HashMap<SocketAddr, (u32, std::time::Instant)>,
    /// The same budget applied to inbound `ExchangeRequest`, which is the frame
    /// that makes us *build and send* an EPX payload. Only the receive side was
    /// bounded, so an authenticated peer could drive an unlimited number of
    /// multi-kilobyte replies out of us with tiny requests. Kept as its own map
    /// rather than sharing `ember_udp_epx_rate` so the two directions of one
    /// exchange cannot eat each other's allowance — a peer legitimately sends us
    /// data and asks for ours inside the same window.
    pub(super) ember_udp_epx_req_rate: HashMap<SocketAddr, (u32, std::time::Instant)>,
    /// Diagnostic counters surfaced via `get_ember_diagnostics`. Increment
    /// from inside `network/mod.rs` (EPX events, peer-count snapshots) or
    /// from `ConnectionBroker::stats()` for broker-owned counters.
    pub(super) ember_diagnostics: EmberDiagnostics,
    /// Peak verified-contact counts, loaded from `ember_dht_highwater.json`
    /// so a restart does not reset the only long-run health signal.
    pub(super) ember_verified_highwater: EmberVerifiedHighwater,
    pub(super) ember_verified_highwater_dirty: bool,
    /// Shared anti-leech client-software filter. Held here so the
    /// settings command path can hot-swap the pattern list without the
    /// upload listener needing to re-subscribe; the upload server
    /// already holds an `Arc` clone of this same handle.
    pub(super) antileech: crate::security::antileech::SharedAntiLeechFilter,
    /// Mapping of ed2k file hash → AICH root hash for EPX payload
    pub(super) aich_root_map: HashMap<[u8; 16], [u8; 20]>,
    /// When each callback placeholder row was inserted (epoch seconds).
    pub(super) callback_row_pending_since: HashMap<(String, String, u16), i64>,
    /// Semaphore limiting concurrent outgoing TCP connections for firewall checks
    pub(super) firewall_connect_semaphore: Arc<tokio::sync::Semaphore>,
    /// Global admission protects both the UDP response and TCP connect-back
    /// sides from spoofed-source amplification.
    pub(super) firewall_req_response_bucket: TokenBucket,
    pub(super) firewall_req_connect_bucket: TokenBucket,
    /// K18: per-IP cooldown timestamps for incoming FirewalledReq. An
    /// attacker with UDP spoof capability can send many FirewalledReq
    /// packets that each trigger an outgoing TCP connect-back attempt
    /// on our end (default 5s timeout, ~16 in flight). A simple 60s
    /// per-IP cooldown + compact size cap blocks that amplification
    /// without hurting legit peers (eMule only rechecks its firewall
    /// status once an hour).
    pub(super) firewall_req_cooldown: HashMap<Ipv4Addr, i64>,
    /// Ember friends currently connected (ember_hash -> last_seen_timestamp)
    pub(super) online_friends: HashMap<[u8; 16], i64>,
    /// Session-bound FIFO correlation for friend browse requests. See
    /// [`browse::PendingBrowseRequest`] for why a request ID alone is
    /// insufficient.
    pub(super) pending_browse_requests: PendingBrowseRequests,
    /// Short-lived dedup for inbound Ember chat messages: ember_hash ->
    /// (last message text, received-at timestamp). Only canonical v2 sessions
    /// can reach this map; the short window suppresses accidental same-session
    /// application retries without accepting generic transfer-path chat.
    pub(super) recent_ember_chat: HashMap<[u8; 16], (String, i64)>,
    /// Shared Ember session map for sending outbound packets to friend connections
    pub(super) ember_sessions: upload_server::EmberSessionMap,
    /// Shared flag: set while the app is shutting down, so the upload listener
    /// stops accepting new connections and terminates active sessions before the
    /// multi-second save sequence tears their state down.
    ///
    /// Shutdown is the *only* thing that raises this, and the name says so on
    /// purpose. Going offline must not: eMule's global Disconnect stops the
    /// server connection and KAD and never touches its listen socket
    /// (`CemuleDlg::CloseConnection`; `CListenSocket::StopListening` is only
    /// called by `OnAccept` shedding load), so a disconnected eMule keeps serving
    /// the peers that already hold a queue slot or know its address. Two earlier
    /// rules tried to raise this on disconnect and both stopped uploads that
    /// should have kept running — see `NetworkCommand::KadDisconnect` and
    /// `handle_server_disconnect`.
    ///
    /// Nothing clears it, because there is no path back from shutdown.
    pub(super) uploads_halted_for_shutdown: Arc<std::sync::atomic::AtomicBool>,
    /// The user asked activity to stop: set by an explicit `KadDisconnect`,
    /// cleared by every path back off `Disconnected`.
    ///
    /// Deliberately not `uploads_halted_for_shutdown`, which answers a different
    /// question — "are we still accepting inbound connections?" — and is raised
    /// only by shutdown, which is not the user asking to go offline. This one is
    /// only ever set by an explicit Disconnect, so it can
    /// gate the outbound side: starting download workers, dialling friends, and
    /// UDP server search, plus whether eD2K auto-reconnect may fire at all.
    ///
    /// Shared rather than a plain `bool` because friend dials outlive the
    /// network task's borrow — one spawned before the click can still be
    /// mid-handshake after it, and the session-insert path has to be able to
    /// see that the answer changed underneath it.
    pub(super) user_offline: Arc<std::sync::atomic::AtomicBool>,
    /// Whether we have successfully registered with the rendezvous server
    pub(super) rendezvous_registered: bool,
    /// Last successful `/register` had intro *and* every pairwise presence
    /// miss, so existing keyed friends cannot resolve us. Kept in sync with
    /// the `ember:friend-discoverable` event; `IsFriendDiscoverable` is
    /// `rendezvous_registered && !last_presence_blocked`.
    pub(super) last_presence_blocked: bool,
    /// Invalidates late initial/heartbeat results after timeout/disconnect.
    pub(super) rendezvous_register_generation: u64,
    /// The beat the next `/register` selects its rooms with. See
    /// [`select_rendezvous_rooms`].
    ///
    /// Apart from the generation above because that one also moves on
    /// failures, the watchdog and resets, each of which skipped a slice of
    /// rooms that was never registered. This advances only when a
    /// registration lands, so a retry publishes the rooms that were missed.
    pub(super) rendezvous_room_beat: u64,
    /// The beat the last successful `/register` used, so neighbor dialing
    /// walks the rooms we were actually published for.
    pub(super) rendezvous_published_beat: u64,
    /// Last time we registered with the rendezvous server (for heartbeat)
    pub(super) rendezvous_last_register: Option<std::time::Instant>,
    /// When the last presence heartbeat was spawned, including failures.
    /// Separated from `rendezvous_last_register` so a failed attempt can
    /// back off without the success-path 120s clock (which is cleared on
    /// error so the first retry is fast).
    pub(super) rendezvous_last_attempt: Option<std::time::Instant>,
    /// Consecutive failed presence heartbeats. Drives
    /// [`presence_failure_retry_secs`]; reset on success.
    pub(super) rendezvous_register_fail_streak: u32,
    /// When the last forced refresh was requested. A registration started
    /// before it may predate what the refresh is for (a reset intro secret, a
    /// new friend), so that attempt's success must not restart the heartbeat
    /// clock and cancel the refresh.
    pub(super) rendezvous_force_register_at: Option<tokio::time::Instant>,
    /// Tracks active outbound friend session tasks to prevent duplicates.
    /// ember_hash -> Instant when the session was started.
    pub(super) outbound_session_tasks: HashMap<[u8; 16], std::time::Instant>,
    /// Whether the initial friend search has been queued after connect
    pub(super) friend_search_initial_done: bool,
    /// Friends still owed a startup presence lookup, drained
    /// [`INITIAL_FRIEND_SEARCH_PER_TICK`] at a time by the bootstrap timer.
    /// Filtered against live state on the way out, so anyone who turns up on
    /// their own before their turn costs nothing.
    pub(super) friend_search_initial_queue: Vec<[u8; 16]>,
    /// When the initial friend search started (for 30-min auto-retry cutoff)
    pub(super) friend_search_started_at: Option<std::time::Instant>,
    /// When the startup sweep began waiting for the network to be ready to
    /// dial friends (see `friends::startup_sweep_ready`).
    pub(super) friend_search_waiting_since: Option<std::time::Instant>,
    /// When the startup sweep's follow-up pass is due. Set once the sweep's
    /// queue has emptied.
    pub(super) friend_search_followup_at: Option<std::time::Instant>,
    /// The follow-up pass has run; there is only ever one per connection.
    pub(super) friend_search_followup_done: bool,
    /// Backoff tracker for friend reconnection: ember_hash -> last attempt time.
    /// Prevents tight reconnect loops when sessions fail immediately.
    pub(super) friend_reconnect_last: HashMap<[u8; 16], std::time::Instant>,
    /// Shared registry of active download trackers — the shutdown path iterates
    /// this to persist `.part.met` files when download tasks are aborted.
    pub(super) tracker_registry: SharedTrackerRegistry,
    /// Cached NAT type info for LowID-to-LowID hole-punch decisions
    pub(super) nat_info: ember::nat::NatInfo,
    /// Invalidates NAT probe results that arrive after a watchdog/disconnect
    /// has superseded the task.
    pub(super) nat_probe_generation: u64,
    /// Invalidates mapping keep-alive (STUN/TCP-hold) cycle results that
    /// arrive after a disconnect has superseded them — a `NetworkState`
    /// field (not a loop-local) specifically so `NetworkCommand::KadDisconnect`
    /// can bump it and stop a stale in-flight result from re-populating
    /// `external_udp_port` / `stun_sourced_udp_port` / advertise ports right
    /// after `reset_stun_keepalive_session` just cleared them.
    pub(super) mapping_ka_generation: u64,
    /// Live-updated mirror of `nat_info` (plus the QUIC endpoint once
    /// available) shared with spawned friend-dial tasks via
    /// `connect_friend_with_fallback`, so a fresh read right before the
    /// hole-punch attempt sees the current values instead of whatever was
    /// true when the task was spawned — see `FriendNatContext`'s doc
    /// comment. Kept in sync wherever `nat_info` or `connection_broker` is
    /// updated.
    pub(super) friend_nat_context: ember::nat::SharedFriendNatContext,
    /// Connection broker for LowID-to-LowID transfers via hole-punch/relay
    pub(super) connection_broker: Option<ember::broker::ConnectionBroker>,
    /// Broker event receiver (fed by ConnectionBroker, consumed in main select loop)
    pub(super) broker_event_rx: Option<mpsc::Receiver<ember::broker::BrokerEvent>>,
    /// Manages relay sessions when this node acts as a relay for other peers
    pub(super) relay_manager: Arc<tokio::sync::Mutex<ember::relay::RelayManager>>,
    /// Peer reputation tracking (score, ban, decay)
    pub(super) reputation: ember::reputation::ReputationManager,
    /// Digest of the relay offer last delivered to each friend, so a steady set
    /// is sent once rather than every tick.
    ///
    /// Keyed by `(session_id, digest)` rather than digest alone. Pruning to live
    /// sessions was supposed to re-offer the set to a friend who reconnects, but
    /// a reconnect reinstates the same Ember hash, so the entry survived and the
    /// friend waited out the refresh bucket — up to ten minutes — before hearing
    /// anything. The session id changes on every new session, which is exactly
    /// the event that should invalidate this.
    pub(super) friend_relay_offer_sent: HashMap<[u8; 16], (u64, u64)>,
    /// Our own Ed25519 public key, so relay admission can recognise our own
    /// attestation coming back to us. Gossip makes that routine: we hand a
    /// friend our attestation, the friend folds it into the set it forwards,
    /// and it returns on the next exchange. Admitting it would let the broker
    /// pick us as our own relay.
    pub(super) local_ed25519_pubkey: [u8; 32],
    /// When each friend's last accepted relay offer was processed.
    ///
    /// Verifying an offer costs up to `MAX_RELAY_ATTESTATIONS` Ed25519
    /// signature checks on the network loop. A friend is authenticated, not
    /// trusted, so nothing stops a malicious or compromised one from sending
    /// offers back to back; this throttles the cost to once per
    /// [`FRIEND_RELAY_OFFER_MIN_INTERVAL`] regardless of how fast they arrive.
    pub(super) friend_relay_offer_seen: HashMap<[u8; 16], std::time::Instant>,
    /// Last unsolicited file offer accepted from each friend, throttling the
    /// prompts one of them can raise. See [`FRIEND_FILE_OFFER_MIN_INTERVAL`].
    pub(super) friend_file_offer_seen: HashMap<[u8; 16], std::time::Instant>,
    /// Ember-native Noise transport. Always initialised at network
    /// startup so the dispatch decision in `handle_udp_packet` can be
    /// gated purely on `settings.ember_native_enabled` — toggling the
    /// flag at runtime is observable on the next packet without
    /// reinitialising state. Sessions are cleared when the flag flips
    /// off so a stale handshake from the "on" period cannot decrypt
    /// later traffic if the user re-enables.
    pub(super) ember_transport: ember::transport::EmberTransport,
    /// Pending `EmberControlMessage::Ping` requests we sent and are
    /// waiting on a `Pong` for. Keyed by the wire `nonce`. Each entry
    /// carries the start time (for RTT) and a oneshot the harness
    /// command awaits with a timeout. Bounded by the cap below so
    /// a misbehaving peer cannot grow the map without limit.
    pub(super) ember_pending_pings: HashMap<u64, (std::time::Instant, oneshot::Sender<std::time::Duration>)>,
    /// Ember-native DHT engine: our Ed25519 DHT identity, the Kademlia
    /// routing table, and the PING/PONG driver. Always constructed at
    /// startup (like `ember_transport`) so the dispatch path can route
    /// DHT frames whenever `ember_native_enabled` is on, without
    /// reinitialising state when the flag toggles. Contacts are learned
    /// from any validly-signed inbound frame and seeded manually via
    /// the harness `add_ember_dht_contact` command.
    pub(super) ember_dht: ember::dht::engine::EmberDht,
    /// Slice 14: per-IP Ember DHT rate limits.
    pub(super) ember_dht_protection: ember::dht::protection::DhtProtection,
    /// Slice 19: observed-IP voting from PONG payloads (NAT self-discovery).
    pub(super) ember_observed_votes: ember::dht::observed::EmberObservedIpVotes,
    /// Expected Ember BLAKE3 digests a transfer will enforce at completion
    /// (ed2k -> digest plus the evidence behind it). Seeded from DHT records,
    /// from the row the user clicked, and from locally hashed files; conflicts
    /// are resolved by [`seed_ember_content_hash`], never by arrival order.
    pub(super) ember_content_hashes: HashMap<[u8; 16], EmberDigestPin>,
    /// Pending Ember DHT `PING` requests awaiting a `PONG`, keyed by the
    /// wire `request_id`. Mirrors `ember_pending_pings` (the control
    /// ping map) and is bounded by `MAX_EMBER_PENDING_PINGS`.
    pub(super) ember_dht_pending_pings:
        HashMap<u32, (std::time::Instant, SocketAddr, oneshot::Sender<std::time::Duration>)>,
    /// Pending Ember DHT `FIND_NODE` requests awaiting a `FOUND_NODE`,
    /// keyed by `request_id`. The waiter receives the contacts the peer
    /// returned. Bounded by `MAX_EMBER_PENDING_PINGS`.
    /// The destination is kept alongside the waiter so an answer has to come
    /// from the peer the query went to, the way `ember_dht_pending_pings`
    /// already requires. Request ids come from one guessable counter, so
    /// matching on the id alone let any peer holding a session answer somebody
    /// else's query with its own contact list.
    pub(super) ember_dht_pending_finds: HashMap<
        u32,
        (
            std::time::Instant,
            SocketAddr,
            oneshot::Sender<Vec<EmberDhtContactInfo>>,
        ),
    >,
    /// Active iterative Ember DHT lookups (slice 4). The state machine
    /// (shortlist, α-parallelism, convergence) lives in `SearchManager`;
    /// the network task drives it by sending `FIND_NODE` frames and
    /// feeding `FOUND_NODE` answers back in.
    pub(super) ember_search: ember::dht::search::SearchManager,
    /// In-flight iterative-lookup queries keyed by the **wire**
    /// `request_id` of the `FIND_NODE` we sent, so an arriving
    /// `FOUND_NODE` can be routed to the right search and shortlist
    /// entry, and stale queries can be expired.
    pub(super) ember_dht_search_requests: HashMap<u32, EmberSearchRequest>,
    /// Iterative-lookup waiters keyed by `search_id`. Resolved with the
    /// closest contacts that responded once the search converges (or
    /// with an empty set if it times out).
    pub(super) ember_dht_pending_lookups: HashMap<u32, oneshot::Sender<Vec<EmberDhtContactInfo>>>,
    /// Value-lookup (`FIND_VALUE`) waiters keyed by `search_id`. Resolved
    /// with the verified record blobs the search gathered once it
    /// converges (or empty if it times out). Kept separate from
    /// `ember_dht_pending_lookups` because a value lookup yields records,
    /// not contacts.
    pub(super) ember_dht_pending_value_lookups: HashMap<u32, oneshot::Sender<Vec<Vec<u8>>>>,
    /// Active keyword/source publishes (slice 5). `PublishManager` tracks
    /// the targeted nodes and their acks; the network task drives it by
    /// sending `STORE_RECORD` frames and feeding `STORE_ACK`s back in.
    pub(super) ember_publish: ember::dht::publish::PublishManager,
    /// In-flight publish `STORE_RECORD`s keyed by the **wire** `request_id`
    /// of the store we sent, so an arriving `STORE_ACK` can be routed to
    /// the right publish and target, and stale stores can be expired.
    pub(super) ember_dht_publish_requests: HashMap<u32, EmberPublishRequest>,
    /// Publish waiters keyed by `publish_id`. Resolved with the store
    /// tally once every targeted node has acked, failed, or timed out.
    pub(super) ember_dht_pending_publishes: HashMap<u32, oneshot::Sender<EmberPublishResult>>,
    /// In-flight maintenance liveness pings (slice 6) keyed by the wire
    /// `request_id`, mapping to the pinged contact and when the ping went
    /// out. A `PONG` clears the entry; the 1-second sweep faults and
    /// eventually evicts contacts whose entry outlives
    /// `EMBER_MAINT_PING_TIMEOUT`. Unlike `ember_dht_pending_pings` these
    /// have no waiter — they exist purely to drive eviction.
    pub(super) ember_dht_maint_pings: HashMap<u32, EmberMaintPing>,
    /// Last time we (re)published an Ember DHT *source* record for each
    /// shared file, keyed by its 16-byte eD2K hash (slice 9). The publish
    /// tick republishes a file only after `EMBER_SOURCE_REPUBLISH` has
    /// elapsed, mirroring KAD's per-file source-publish schedule but driven
    /// independently of KAD connectivity so it works on a KAD-less network.
    pub(super) ember_source_publish_at: HashMap<[u8; 16], std::time::Instant>,
    /// Unix-second copy of the source-publish stamps, written to known.met
    /// so a restart does not treat the whole library as never-published.
    pub(super) ember_source_publish_unix: HashMap<[u8; 16], u32>,
    /// Last time we (re)published Ember DHT *keyword* records for each
    /// shared file, keyed by its 16-byte eD2K hash (slice 8). The publish
    /// tick republishes a file's keywords only after
    /// `EMBER_KEYWORD_REPUBLISH` has elapsed.
    pub(super) ember_keyword_publish_at: HashMap<[u8; 16], std::time::Instant>,
    /// Unix-second copy of the keyword-publish stamps, written to known.met
    /// so a restart does not republish every keyword on launch.
    pub(super) ember_keyword_publish_unix: HashMap<[u8; 16], u32>,
    /// Shared files whose Ember DHT source record has been acknowledged by
    /// at least one storer, keyed by 16-byte eD2K hash. Drives the Library
    /// "Ember" badge, the same way `PublishManager`'s source timestamps
    /// drive the KAD badge.
    ///
    /// Deliberately *not* derived from `ember_source_publish_at`: that map
    /// is a scheduling clock and `charge_ember_publish_round` stamps it
    /// for rounds that were never confirmed, so a file nobody stored would
    /// otherwise light up the badge.
    pub(super) ember_published_sources: HashSet<[u8; 16]>,
    /// In-flight Ember DHT *keyword* searches started for a user search
    /// (slice 10), keyed by `search_id` -> the originating search context.
    /// Distinct from the dev value-lookup waiters
    /// (`ember_dht_pending_value_lookups`): completion feeds the streaming
    /// search-results pipeline rather than a oneshot.
    pub(super) ember_keyword_searches: HashMap<u32, EmberKeywordSearch>,
    /// Keyword-search result batches gathered by completed Ember DHT
    /// lookups (slice 10), awaiting async emit. Completion is detected
    /// synchronously in `maybe_finish_ember_search`, but emitting needs the
    /// async enrich pipeline + app_handle, so batches are buffered here and
    /// drained on the next `ember_search_timer` tick.
    pub(super) ember_pending_keyword_results: Vec<EmberKeywordResultBatch>,
    /// In-flight Ember DHT source lookups for active/pending downloads
    /// (slice 9), keyed by `search_id`, mapping to the `(transfer_id,
    /// file_hash)` the lookup is for so `FOUND_VALUE` records can be parsed
    /// into sources and injected into the matching download.
    pub(super) ember_download_source_searches: HashMap<u32, (String, [u8; 16])>,
    /// Per-download Ember DHT source-search throttle (slice 9), keyed by
    /// `transfer_id` → `(last_search_unix, search_count)`. Mirrors
    /// `active_kad_search_state`: the `search_count` drives the
    /// `ember_source_search_interval` backoff so a long-running download
    /// queries the DHT eagerly at first, then progressively less often.
    pub(super) ember_source_search_state: HashMap<String, (i64, u32)>,
    /// Sources parsed from completed Ember DHT source lookups, awaiting
    /// async injection into the matching downloads (slice 9). The
    /// completion point (`maybe_finish_ember_search`) is synchronous, but
    /// injection (`handle_epx_sources`) is async, so results are buffered
    /// here and drained on the next `ember_search_timer` tick.
    pub(super) ember_pending_source_injections: Vec<([u8; 16], Vec<ember::dht::publish::DiscoveredSource>)>,
    /// Buddy-relayed Ember `CALLBACK`s asking us (firewalled publisher) to
    /// connect-and-serve the searcher. Drained on the search timer, which
    /// has `connect_serve_tx`.
    pub(super) ember_pending_callback_connects: Vec<ember::dht::engine::CallbackConnect>,
    /// Firewalled source records waiting for `PROXY_STORE_ACK` before overlay
    /// `STORE_BATCH`. Keyed by `(buddy, request_id)`.
    pub(super) ember_pending_proxy_overlay: HashMap<(ember::dht::EmberNodeId, u32), EmberPendingProxyOverlay>,
    /// Channel gossip ids already persisted or flooded this session.
    pub(super) channel_gossip_seen: HashMap<[u8; 16], std::time::Instant>,
    pub(super) channel_gossip_seen_order: VecDeque<[u8; 16]>,
    /// Timestamps of recent relayed `CHANNEL_MSG` frames (token bucket).
    pub(super) channel_gossip_sent_times: VecDeque<std::time::Instant>,
    /// The same, for frames this user originated.
    ///
    /// Separate from the relay bucket because the two deserve opposite
    /// treatment when the room is busy. Relaying is work done on the mesh's
    /// behalf and shedding it is how a flood stops spreading; a line the user
    /// typed is the one frame in the system that has no second chance, since
    /// the local copy is already stored and on screen, so dropping it shows
    /// them a message the room never received.
    pub(super) channel_gossip_local_times: VecDeque<std::time::Instant>,
    /// Originated gossip that had no neighbor (or hit the local send budget)
    /// and is waiting to be tried again.
    pub(super) channel_origin_retry: VecDeque<(std::time::Instant, Vec<u8>)>,
    /// Delivery verdicts for originated lines — `(channel_id, msg_id,
    /// delivery)` — buffered until the tick that can persist and emit them.
    /// See [`note_channel_delivery`].
    pub(super) channel_delivery_notes: VecDeque<([u8; 16], [u8; 16], i64)>,
    /// Where a full verdict buffer is flushed from outside the tick.
    pub(super) channel_delivery_sink: (Arc<Database>, tauri::AppHandle),
    /// Inbound `CHANNEL_MSG` timestamps keyed by the DHT hop's node id.
    pub(super) channel_gossip_from_times: HashMap<[u8; 16], VecDeque<std::time::Instant>>,
    /// Room row plus derived content keys, memoised for the packet paths.
    /// See [`cached_channel_view`].
    pub(super) channel_view_cache: HashMap<[u8; 16], CachedChannelView>,
    /// Inbound chat timestamps keyed by (room, signed author), so one member
    /// cannot flood a room by spreading the load across many hops.
    pub(super) channel_gossip_author_times:
        HashMap<([u8; 16], [u8; 32]), VecDeque<std::time::Instant>>,
    /// Inbound catch-up requests keyed by (room, signed requester), on their
    /// own far tighter budget than chat: answering one costs us up to
    /// `CHANNEL_HISTORY_SYNC_MAX` sealed unicasts, so it is the one frame where
    /// the asker spends less than we do.
    pub(super) channel_history_sync_times:
        HashMap<([u8; 16], [u8; 32]), VecDeque<std::time::Instant>>,
    /// Inbound typing signals keyed by (room, signed author). Apart from the
    /// chat budget so a member's typing cannot spend what their next line needs.
    pub(super) channel_typing_recv_times:
        HashMap<([u8; 16], [u8; 32]), VecDeque<std::time::Instant>>,
    /// Typing signals this device has sent, per room. Each one is a datagram
    /// to every reachable member, so the ceiling holds whatever the UI asks.
    pub(super) channel_typing_sent_times: HashMap<[u8; 16], VecDeque<std::time::Instant>>,
    /// Last history-sync request per (channel_id, neighbor pubkey), stamped on
    /// the attempt whether or not any path to the neighbor was found.
    pub(super) channel_history_sync_at: HashMap<([u8; 16], [u8; 32]), std::time::Instant>,
    /// Latest publish of each owned room's committed handoff record: the
    /// publish id while one is out, and when it was started.
    pub(super) channel_handoff_publishes: HashMap<[u8; 16], (Option<u32>, i64)>,
    /// Rooms whose handoff is being finished right now. Shared with the tasks
    /// that do it, so the publish acknowledgement and the periodic driver
    /// cannot both hand the registry name over.
    pub(super) channel_handoff_completing: Arc<std::sync::Mutex<HashSet<[u8; 16]>>>,
    /// Rooms whose committed handoff has already been reported as not landing,
    /// so the report goes out once per window rather than every pass.
    pub(super) channel_handoff_failure_noted: HashSet<[u8; 16]>,
    /// Consecutive history-sync attempts that found no path to the neighbor,
    /// per (channel_id, neighbor pubkey). Cleared on a send; drives
    /// [`ember::channel::history_sync_retry_secs`].
    pub(super) channel_history_sync_failures: HashMap<([u8; 16], [u8; 32]), u32>,
    /// The room's [`Self::channel_history_sync_ingested`] count when we last
    /// asked this neighbor.
    ///
    /// The stamp above is written when a request is *sent*, so it cannot tell
    /// a neighbor who had nothing to add from one that is still feeding us a
    /// backlog — both wait the full five minutes. A reply is not a frame we
    /// can correlate (it arrives as ordinary gossip), but its lines have a
    /// shape of their own. When more of them have landed since the ask, the
    /// gap is still closing and this neighbor is worth asking again on the
    /// shorter [`ember::channel::CHANNEL_HISTORY_WALK_SECS`] rather than the
    /// idle interval. The room's newest timestamp cannot stand in for this:
    /// live chat advances it too.
    pub(super) channel_history_sync_mark: HashMap<([u8; 16], [u8; 32]), i64>,
    /// Lines stored per room from catch-up-shaped frames this session. See
    /// [`ember::channel::gossip_is_catch_up_shaped`].
    pub(super) channel_history_sync_ingested: HashMap<[u8; 16], i64>,
    /// In-flight FIND_VALUE of channel presence keys (`search_id` → channel).
    pub(super) ember_channel_presence_searches: HashMap<u32, [u8; 16]>,
    /// Presence blobs accumulated for a channel while any FIND_VALUE for it
    /// is still in flight. Applied only when the last search completes, so
    /// current and previous epoch are newest-wins together rather than two
    /// independent races.
    pub(super) ember_channel_presence_buffer: HashMap<[u8; 16], Vec<Vec<u8>>>,
    /// Presence blobs waiting for DB upsert + UI emit (async drain).
    pub(super) ember_pending_channel_presence: Vec<([u8; 16], Vec<Vec<u8>>)>,
    /// Last presence FIND_VALUE start per channel.
    pub(super) channel_presence_fetch_at: HashMap<[u8; 16], i64>,
    /// The one room the user currently has open, if any.
    ///
    /// Presence costs are paid per room, and a user who has joined thirty of
    /// them is reading one. Walking and beating that one harder is the whole
    /// difference between a roster that is right when somebody looks at it and
    /// one that is right five minutes later.
    pub(super) channel_focused: Option<[u8; 16]>,
    /// Last mesh presence beat per channel.
    pub(super) channel_beacon_beat_at: HashMap<[u8; 16], i64>,
    /// Freshest beacon held per room, keyed by the member that signed it.
    ///
    /// Bounded by the roster, because a beacon is only kept for a member the
    /// roster already admits — the cap and eviction rules in
    /// `upsert_channel_member` are what stop a flood of invented identities
    /// becoming gossip neighbors, and this map must not be a way around them.
    pub(super) channel_beacons: HashMap<[u8; 16], HashMap<[u8; 32], ember::channel::PresenceBeacon>>,
    /// Last time a member's beacon was passed on as a flood, per (room, member).
    pub(super) channel_beacon_flood_at: HashMap<([u8; 16], [u8; 32]), i64>,
    /// Rolling `(window start, count)` of members a room's roster has gained
    /// from beacons, which is the one thing this layer must not make cheap.
    pub(super) channel_beacon_inserts: HashMap<[u8; 16], (i64, usize)>,
    /// Roster rows whose `last_seen` moved since the last presence emit.
    ///
    /// Coalesced rather than emitted as they land: a busy room touches the same
    /// handful of rows many times a second, and the UI only needs to know where
    /// they ended up.
    pub(super) channel_presence_dirty: HashMap<[u8; 16], HashMap<[u8; 32], i64>>,
    /// In-flight FIND_VALUE of channel moderation keys (`search_id` → channel).
    pub(super) ember_channel_moderation_searches: HashMap<u32, [u8; 16]>,
    /// Moderation blobs waiting for DB apply + UI emit (async drain), with how
    /// many peers answered the search that produced them. Zero means we learned
    /// nothing either way, which succession has to tell apart from a room whose
    /// owner really has stopped publishing.
    pub(super) ember_pending_channel_moderation: Vec<([u8; 16], Vec<Vec<u8>>, usize)>,
    /// Last moderation FIND_VALUE start per channel.
    pub(super) channel_moderation_fetch_at: HashMap<[u8; 16], i64>,
    /// Last owner moderation STORE per channel.
    pub(super) channel_moderation_publish_at: HashMap<[u8; 16], i64>,
    /// Last Channel-username refresh against Rendezvous.
    pub(super) channel_username_refresh_at: i64,
    /// Rendezvous base URL, refreshed from settings on the channel heartbeat.
    /// Cached because the gossip handlers need it to hand a room's registry
    /// name to its successor, and they are several layers below the loop that
    /// holds `AppSettings`.
    pub(super) rendezvous_url: String,
    /// Member Ed25519 → Noise static key from presence extra (no IP).
    pub(super) ember_channel_noise_keys: HashMap<[u8; 32], [u8; 32]>,
    /// When `channel_member_touches` was last written through to SQLite. See
    /// [`flush_channel_member_touches`].
    pub(super) channel_member_touch_flushed_at: Option<std::time::Instant>,
    /// Channel roster as last read from SQLite, and when. See
    /// [`channels_lite_cached`].
    pub(super) channel_roster_cache: Option<(Arc<Vec<crate::storage::database::StoredChannel>>, std::time::Instant)>,
    /// Last rendezvous lookup attempt per neighbor Ed25519 pubkey.
    pub(super) channel_neighbor_lookup_at: HashMap<[u8; 32], std::time::Instant>,
    pub(super) channel_neighbor_lookup_inflight: HashSet<[u8; 32]>,
    /// Earliest tick at which [`maybe_dial_channel_neighbors`] should read the
    /// member roster again. `None` means "next tick". See
    /// [`CHANNEL_NEIGHBOR_IDLE_RESCAN`].
    pub(super) channel_neighbor_scan_after: Option<std::time::Instant>,
    /// Live channel-capability WebSocket relays (`peer Ed25519` → outbound).
    ///
    /// Keyed with the session id that registered the outbox so a close can be
    /// matched against it — see [`ChannelRelayEvent::Closed`].
    pub(super) channel_relay_outboxes: HashMap<[u8; 32], (u64, mpsc::Sender<Vec<u8>>)>,
    /// Peers with a session being negotiated but not yet open.
    ///
    /// The duplicate guard used to read `channel_relay_outboxes`, which is only
    /// populated once the ticket dance, the WebSocket connect and the handshake
    /// have all finished — up to ~55 seconds during which the guard saw nothing
    /// and a second session was started for the same peer.
    pub(super) channel_relay_pending: HashSet<[u8; 32]>,
    pub(super) channel_relay_offer_at: HashMap<[u8; 32], std::time::Instant>,
    /// In-flight FIND_VALUE of channel handoff keys (`search_id` → old id).
    pub(super) ember_channel_handoff_searches: HashMap<u32, [u8; 16]>,
    pub(super) ember_pending_channel_handoff: Vec<([u8; 16], Vec<Vec<u8>>)>,
    pub(super) channel_handoff_fetch_at: HashMap<[u8; 16], i64>,
    /// Our Ed25519 seed, for deriving the pairwise key that authenticates
    /// transfer frames. Held here because the gossip handlers have to verify
    /// an inbound frame before anything else looks at it, and they are far
    /// from the command loop that owns the identity.
    pub(super) local_ed25519_seed: [u8; 32],
    /// Ember Transfer: files we have offered or are sending, by transfer id.
    pub(super) xfer_send: HashMap<[u8; 16], ember::xfer::SendState>,
    /// Ember Transfer: files we accepted and are pulling in.
    pub(super) xfer_recv: HashMap<[u8; 16], ember::xfer::RecvState>,
    /// Where [`finish_xfer_recv`] posts a verified transfer back to the event
    /// loop. Held here rather than threaded through the four frames between
    /// the loop and the block handler that completes a transfer.
    pub(super) xfer_finish_tx: mpsc::UnboundedSender<XferFinishResult>,
    /// Verifications handed to the blocking pool that the loop has not yet
    /// applied. Shutdown drains exactly this many results before it tears the
    /// socket down, so a transfer that finished hashing as the user quit still
    /// gets its completion frame instead of being timed out by the sender.
    pub(super) xfer_finish_in_flight: usize,
    /// `last_seen` touches waiting to be written, keyed by `(room, member)` and
    /// holding the newest timestamp seen. Drained by
    /// [`flush_channel_member_touches`] on its own interval.
    pub(super) channel_member_touches: HashMap<([u8; 16], [u8; 32]), i64>,
    /// Offers waiting on the user to accept or decline.
    pub(super) xfer_pending: HashMap<[u8; 16], ember::xfer::PendingOffer>,
    /// Data-block send budget. Separate from the chat one on purpose — see
    /// [`xfer_block_rate_ok`].
    pub(super) xfer_block_times: VecDeque<std::time::Instant>,
    /// Upload allowance taken from the limiter but not yet spent on a block.
    /// See [`xfer_upload_allowance_ok`].
    pub(super) xfer_upload_credit: u64,
    /// Mirror of `channel_file_offers`, so an inbound offer can be judged
    /// without reaching back into the settings the command loop owns.
    pub(super) xfer_offer_policy: String,
    /// Read-only view of the friends list, for the `"friends"` offer policy.
    pub(super) xfer_friend_hashes: crate::app_state::SharedFriendHashes,
    /// Chat attachments a friend has offered us that nobody has answered yet,
    /// with what accepting one needs. In memory only: see
    /// [`chat_attach::sweep_interrupted`] for what a restart does to them.
    pub(super) attach_inbound: HashMap<[u8; 16], chat_attach::InboundAttach>,
    /// Receives in flight, so a cancel from either side can stop one.
    pub(super) attach_fetches: HashMap<[u8; 16], tokio::task::JoinHandle<()>>,
    /// Recent auto-accepts per friend, as `(when, bytes)`, for the budget that
    /// stops a friend filling the disk one small file at a time. See
    /// [`chat_attach::auto_accept_allowed`].
    pub(super) attach_auto_log: HashMap<[u8; 16], VecDeque<(i64, u64)>>,
    /// In-flight FIND_VALUE of a content-key epoch record (`search_id` →
    /// channel + epoch).
    pub(super) ember_channel_epoch_searches: HashMap<u32, ([u8; 16], i64)>,
    /// Epoch blobs waiting to be opened and stored (async drain).
    pub(super) ember_pending_channel_epoch: Vec<([u8; 16], i64, Vec<Vec<u8>>)>,
    /// Last epoch FIND_VALUE start per channel.
    ///
    /// Per channel rather than per (channel, epoch): we only ever chase the one
    /// epoch the owner currently advertises, and keying on the epoch too meant
    /// a long-lived client accumulated an entry for every rotation a room had
    /// ever had, with nothing to remove them.
    pub(super) channel_epoch_fetch_at: HashMap<[u8; 16], i64>,
    /// In-flight FIND_VALUE of a succession claim (`search_id` → channel).
    pub(super) ember_channel_claim_searches: HashMap<u32, [u8; 16]>,
    /// Claim blobs waiting to be verified against the owner's nomination.
    pub(super) ember_pending_channel_claim: Vec<([u8; 16], Vec<Vec<u8>>)>,
}

/// One in-flight iterative-lookup `FIND_NODE`, tracked by the network
/// task so a matching `FOUND_NODE` (or a timeout) can be applied to the
/// owning [`ember::dht::search::SearchManager`] search. The expected
/// responder id is held inside the search itself (`pending_requests`),
/// which `process_response` uses to reject forged or misrouted answers.
pub(super) struct EmberSearchRequest {
    /// The owning search.
    pub(super) search_id: u32,
    /// The per-search request id `next_to_query` handed out (the
    /// correlation token `process_response` / `mark_failed` expect).
    pub(super) per_search_req_id: u32,
    /// When the staleness sweep should give up on this query.
    ///
    /// A deadline rather than a send time because the budget is not the same
    /// for every query: one queued behind a Noise handshake has not reached the
    /// peer yet, and charging it the ordinary budget expired it before it had
    /// been asked anything — which on a cold table is every first contact.
    pub(super) deadline: std::time::Instant,
    /// Unix time the query was issued, so the sweep can tell whether the peer
    /// has been heard from since. Same rule as the liveness ping: a peer that
    /// answered something else while this query was outstanding is alive, and
    /// charging it a strike walks a working contact toward eviction.
    pub(super) sent_unix: i64,
}
