use crate::network::kad::types::{DEFAULT_TCP_PORT, DEFAULT_UDP_PORT};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub id: String,
    pub name: String,
    pub path: String,
    pub size: u64,
    pub hash: String,
    /// AICH root hash (SHA-1 Merkle tree over 180KB blocks), hex-encoded
    #[serde(default)]
    pub aich_hash: String,
    /// Streaming BLAKE3 of file contents (slice 18), hex-encoded. Empty when
    /// unknown (legacy share / not yet hashed). Discovery still keys off
    /// eD2K MD4 in [`Self::hash`].
    #[serde(default)]
    pub ember_file_hash: String,
    pub extension: String,
    pub modified_at: i64,
    /// Upload priority: "verylow", "low", "normal", "high", "release", "auto"
    #[serde(default = "default_file_priority")]
    pub priority: String,
    /// Requests received this session
    #[serde(default)]
    pub requests: u32,
    /// Requests accepted this session
    #[serde(default)]
    pub accepted: u32,
    /// Bytes uploaded for this file this session
    #[serde(default)]
    pub bytes_transferred: u64,
    /// All-time requests (from known.met)
    #[serde(default)]
    pub alltime_requests: u32,
    /// All-time accepted requests (from known.met)
    #[serde(default)]
    pub alltime_accepted: u32,
    /// All-time bytes uploaded for this file (from known.met)
    #[serde(default)]
    pub alltime_transferred: u64,
    /// Number of known complete sources
    #[serde(default)]
    pub complete_sources: u32,
    /// Folder path (directory containing the file)
    #[serde(default)]
    pub folder: String,
    /// Whether this file is actively shared (user can toggle off to stop publishing)
    #[serde(default = "default_true")]
    pub shared: bool,
    /// Restricts an otherwise-shared file to mutual friends. Only meaningful
    /// while `shared` is true. A friends-only file is never offered to an
    /// ed2k server, published to KAD, listed in a public browse answer, or
    /// served to a peer that is not an authenticated mutual friend — hiding
    /// it from browse alone would still leak it through search.
    #[serde(default)]
    pub friends_only: bool,
    /// Whether this file is currently published on KAD (runtime status)
    #[serde(default)]
    pub shared_kad: bool,
    /// Whether this file is currently offered to an ed2k server (runtime status)
    #[serde(default)]
    pub shared_ed2k: bool,
    /// Whether a source record for this file is live on the Ember DHT
    /// (runtime status). Set only once storers have acknowledged the
    /// publish, so it means "other Ember users can find this", not
    /// "we tried".
    #[serde(default)]
    pub shared_ember: bool,
}

impl FileInfo {
    /// True when this file may be advertised to the open network: offered to
    /// an ed2k server, published to KAD, or listed in a public browse answer.
    /// Every such path must go through this rather than testing `shared`
    /// directly, otherwise a friends-only file stays hidden from browse but
    /// remains discoverable by search.
    #[inline]
    pub fn is_public_listable(&self) -> bool {
        self.shared && !self.friends_only
    }

    /// True when this file may be listed to, or served to, an authenticated
    /// mutual friend. Friends see public and friends-only shares alike.
    #[inline]
    pub fn is_friend_visible(&self) -> bool {
        self.shared
    }
}

fn default_true() -> bool {
    true
}

fn default_filename_cleanups() -> String {
    crate::search::cleanup::DEFAULT_CLEANUP_STRINGS.to_string()
}

fn default_file_priority() -> String {
    "normal".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub addresses: Vec<String>,
    pub nickname: String,
    pub last_seen: i64,
    pub files_shared: u32,
    pub banned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transfer {
    pub id: String,
    pub file_name: String,
    pub file_hash: String,
    pub peer_id: String,
    pub peer_name: String,
    pub direction: TransferDirection,
    pub status: TransferStatus,
    pub progress: f64,
    pub speed: u64,
    pub total_size: u64,
    /// Session transferred bytes (eMule: GetTransferred). For uploads this
    /// is cumulative wire bytes and may exceed [`total_size`] when the peer
    /// re-requests blocks.
    pub transferred: u64,
    /// Unique completed size (eMule: GetCompletedSize). For downloads this
    /// includes resumed data; for uploads it is unique per-part coverage
    /// this session (re-requests do not inflate it).
    #[serde(default)]
    pub completed_size: u64,
    pub started_at: i64,
    #[serde(default)]
    pub failure_reason: Option<String>,
    #[serde(default)]
    pub failure_kind: Option<String>,
    #[serde(default)]
    pub failure_stage: Option<String>,
    /// Priority for this transfer, using eMule's full ladder:
    /// "verylow" | "low" | "normal" | "high" | "release" | "auto".
    ///
    /// Interpreted differently depending on [`direction`](TransferDirection):
    /// - For downloads: relative source-slot allocation across our own
    ///   transfers (higher = more in-flight source requests).
    /// - For uploads: remote slot ranking when a peer is in our upload queue
    ///   (higher = earlier slot grant).
    ///
    /// The shared upload-priority stored on a [`FileInfo`] is copied into the
    /// upload-direction [`Transfer::priority`] when a peer connects, so both
    /// fields share a single domain to simplify IPC and keep eMule
    /// compatibility.
    #[serde(default = "default_priority")]
    pub priority: String,
    #[serde(default)]
    pub sources: u32,
    #[serde(default)]
    pub active_sources: u32,
    #[serde(default)]
    pub queued_sources: u32,
    /// Best queue rank across active sources (eMule QR display)
    #[serde(default)]
    pub queue_rank: Option<u32>,
    /// Timestamp when a complete source was last seen (eMule: lastseencomplete)
    #[serde(default)]
    pub last_seen_complete: Option<i64>,
    /// Timestamp of last data reception (eMule: GetLastReceptionDate)
    #[serde(default)]
    pub last_received: Option<i64>,
    #[serde(default = "default_transfer_health")]
    pub health: TransferHealth,
    #[serde(default)]
    pub health_reason: Option<String>,
    #[serde(default)]
    pub stalled_since: Option<i64>,
    /// Category name (eMule: category tabs)
    #[serde(default)]
    pub category: String,
    /// Upload: how long client waited in queue before the slot was granted,
    /// in **seconds** (eMule: GetWaitTime). A fixed snapshot taken once at
    /// grant time, not a live counter — unlike `upload_time` below, this is
    /// never updated again for the life of the row. The frontend multiplies
    /// by 1000 before formatting; keep this doc's unit in sync with
    /// `UploadEventKind::Started::wait_seconds`, which is where the value
    /// actually comes from.
    #[serde(default)]
    pub wait_time: u64,
    /// Upload: how long the upload has been active (ms) (eMule: GetUpStartTimeDelay)
    #[serde(default)]
    pub upload_time: u64,
    /// A4AF (Asked For Another File) source count
    #[serde(default)]
    pub a4af_sources: u32,
    /// Max source limit for this file
    #[serde(default)]
    pub max_sources: u32,
    /// eMule-style preview priority: download first and last parts first
    #[serde(default)]
    pub preview_priority: bool,
    /// True when this download has enough verified data for `preview_file` to
    /// succeed right now: a previewable media type plus the first ED2K part
    /// (covering the first 256 KB) fully downloaded and MD4-verified. Computed
    /// live from tracker state; drives the UI's Preview-button enablement so
    /// the action is greyed out until a preview would actually work.
    #[serde(default)]
    pub preview_ready: bool,
    /// Sources discovered via Ember Peer Exchange
    #[serde(default)]
    pub ember_sources: u32,
    /// Client software name (uploads only, e.g. "eMule 0.50")
    #[serde(default)]
    pub client_software: String,
    /// ISO country code of the peer (uploads only, e.g. "DE")
    #[serde(default)]
    pub country_code: Option<String>,
    /// ED2K user hash of the peer (uploads only, 32 hex chars)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_hash: Option<String>,
    /// Ember identity of the peer (uploads only). Friends are keyed by this,
    /// not [`user_hash`]; the uploads-pane Add Friend action must use it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ember_hash: Option<String>,
    /// Optional trusted AICH master supplied by an ed2k link/collection.
    /// This is local verification policy only and does not alter ordinary
    /// MD4-only eMule transfers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_aich: Option<String>,
    /// Optional Ember content BLAKE3 (64 hex chars) supplied by an ed2k
    /// `eh=` link, friend browse/offer, or collection entry. Local
    /// verification policy; omitted from IPC when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ember_file_hash: Option<String>,
    /// Absolute path of the finished file on disk (downloads only).
    ///
    /// Completion moves the `.part` to `Downloads/<name>`, but
    /// `move_part_to_final` deduplicates against a pre-existing file by
    /// appending ` (n)` to the stem. Reconstructing the path from
    /// `file_name` alone therefore points at the wrong file whenever a
    /// name collision occurred. We capture the real destination here so
    /// Open/Reveal target exactly the file we wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_path: Option<String>,
    /// Upload-direction only: hex bitmap of ED2K parts fully served to
    /// this peer during the current session (byte index = `part / 8`,
    /// bit index = `part % 8`, LSB-first within each byte). Drives the
    /// eMule-style chunked "Up Status" parts bar in the UI — the analog
    /// of eMule's `m_DoneBlocks_list` green fill in `DrawUpStatusBar`.
    /// `None` for downloads and for uploads that have not yet completed
    /// a full part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_part_status: Option<String>,
    /// Upload-direction only: total ED2K part count of the file
    /// (`ceil(total_size / PARTSIZE)`), paired with [`up_part_status`]
    /// so the UI renders the correct number of segments.
    ///
    /// [`up_part_status`]: Transfer::up_part_status
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_part_count: Option<u32>,
    /// Upload-direction only: hex bitmap (same packing as [`up_part_status`],
    /// shares [`up_part_count`]) of the ED2K parts the downloader advertised it
    /// already had at request time — eMule's `m_abyUpPartStatus`. Drives the
    /// dark "peer already has" shading drawn beneath the green served-this-
    /// session fill on the parts bar. `None` when the peer advertised no parts
    /// or didn't send an extended request.
    ///
    /// [`up_part_status`]: Transfer::up_part_status
    /// [`up_part_count`]: Transfer::up_part_count
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_peer_part_status: Option<String>,
    /// Downloads only: the file's Ember content BLAKE3 was checked against
    /// `nodes_ember.dat`/DHT-sourced hash during this completion and matched
    /// (see `DownloadEvent::Completed::ember_verified`). `false` covers both
    /// "no Ember hash was known to check" and the crash-recovery re-verify
    /// paths, which only re-check the ed2k/AICH hash — so this only ever
    /// claims a check that actually ran.
    #[serde(default)]
    pub ember_verified: bool,
}

fn default_priority() -> String {
    "normal".to_string()
}

fn default_transfer_health() -> TransferHealth {
    TransferHealth::Healthy
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TransferDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TransferStatus {
    Searching,
    Queued,
    Active,
    Paused,
    /// eMule "Stopped": removed from active download but not deleted (different from Paused)
    Stopped,
    Verifying,
    Completing,
    Completed,
    Failed,
    /// Waiting for hash verification after loading
    Hashing,
    /// Insufficient disk space
    Insufficient,
    /// No needed parts available from any source
    NoneNeeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferHealth {
    Healthy,
    Degraded,
    Stalled,
}

/// Per-source detail for a download (eMule-style source list)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    pub ip: String,
    pub port: u16,
    pub status: SourceStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_rank: Option<u32>,
    pub speed: u64,
    pub transferred: u64,
    #[serde(default)]
    pub client_software: String,
    #[serde(default)]
    pub peer_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available_parts: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_parts: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    /// Stable peer identity (eD2k user hash). Mirrors eMule's
    /// `CUpDownClient` identity: a peer keeps this across connection
    /// direction and port changes, so it is used to coalesce rows for the
    /// same peer that would otherwise appear twice — once at its advertised
    /// listening port (from server/KAD/SX discovery) and once at the
    /// ephemeral outbound port of an adopted inbound (LowID/callback/
    /// push-grant) connection. `None` when the identity isn't known yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_hash: Option<[u8; 16]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Connecting,
    WaitCallback,
    Queued,
    QueueFull,
    NoNeededParts,
    Stalled,
    Transferring,
    Completed,
    Failed,
    /// A friend we cannot dial, which we have asked over their friend session
    /// to reach us instead (`OP_EMBER_XFER_REQ`). Distinct from
    /// [`Self::WaitCallback`], which is the eD2K server / KAD-buddy callback:
    /// this one needs no server, no buddy, and no HighID on either side.
    FriendConnect,
    /// A friend source with no usable transport in either direction, because
    /// we sit behind a symmetric NAT. Shown rather than dropped so the cause
    /// is visible; it clears by itself once our reachability changes.
    Unreachable,
}

/// Media metadata for a search hit (eMule `FT_MEDIA_*` tags). Each field is
/// optional because a remote node only fills the ones it knows. Grouped into a
/// single optional struct so a hit with no media info serializes to nothing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MediaMetadata {
    /// Playback length in whole seconds (eMule `FT_MEDIA_LENGTH`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<u32>,
    /// Bitrate in kbps (eMule `FT_MEDIA_BITRATE`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitrate: Option<u32>,
    /// Codec label, e.g. "mp3", "h264" (eMule `FT_MEDIA_CODEC`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artist: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub album: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

impl MediaMetadata {
    /// True when no field carries a value (so callers can collapse to `None`).
    pub fn is_empty(&self) -> bool {
        self.duration.is_none()
            && self.bitrate.is_none()
            && self.codec.is_none()
            && self.artist.is_none()
            && self.album.is_none()
            && self.title.is_none()
    }

    /// Wrap in `Some` only when at least one field is set.
    pub fn into_option(self) -> Option<MediaMetadata> {
        if self.is_empty() {
            None
        } else {
            Some(self)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub file: FileInfo,
    pub peer_id: String,
    pub peer_name: String,
    pub availability: u32,
    pub file_type: String,
    pub source_addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rating: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Media metadata (duration/bitrate/codec/artist/album/title) when the
    /// source advertised any (eMule `FT_MEDIA_*`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<MediaMetadata>,
    #[serde(default)]
    pub spam_rating: u32,
    #[serde(default)]
    pub is_spam: bool,
    #[serde(default)]
    pub clean_name: String,
    /// Where the hit came from: `KAD`, `Server`, `UDP`, `Local`, `Notes`, or combined (e.g. `KAD · Server`).
    #[serde(default)]
    pub result_origin: String,
    /// eD2k server IP this hit was learned from (connected TCP server or UDP
    /// reply source). Used when marking spam so server reputation can train,
    /// and when explaining a row so the tooltip matches list scoring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_server_ip: Option<String>,
    /// Reasons from the enrichment pass that set `spam_rating` / `is_spam`.
    /// The search UI prefers this over a second one-off explain call, which
    /// cannot reconstruct batch-local heuristics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spam_reasons: Vec<String>,
}

/// Response from [`crate::commands::transfers::start_download`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartDownloadResponse {
    pub transfer_id: String,
    /// True when this file was already in the active download queue (same ed2k hash).
    pub already_queued: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub connected_peers: u32,
    pub upload_speed: u64,
    pub download_speed: u64,
    pub total_uploaded: u64,
    pub total_downloaded: u64,
    pub status: NetworkStatus,
    pub external_ip: String,
    pub firewalled: bool,
    pub buddy_status: String,
    pub upnp_mapped: bool,
    pub stores_acknowledged: u32,
    pub kad_users_estimate: u32,
    #[serde(default)]
    pub tcp_status: String,
    #[serde(default)]
    pub udp_status: String,
    /// STUN-probed NAT class (`ember::nat::NatType` debug name), or `"Unknown"`
    /// before the probe resolves. Surfaced because it decides whether friend
    /// hole-punching can work at all: a symmetric NAT re-maps per destination,
    /// so the port we register with the rendezvous server is not the port a
    /// friend would arrive on, and two symmetric peers cannot punch to each
    /// other at all.
    #[serde(default)]
    pub nat_type: String,
    /// Ember Peer Exchange: total unique Ember peers encountered this session
    #[serde(default)]
    pub ember_peers: u32,
    /// Ember Peer Exchange: total sources received via EPX this session
    #[serde(default)]
    pub epx_sources_received: u32,
    /// Current eD2K server connection status: "connected", "connecting", or "disconnected"
    #[serde(default)]
    pub server_status: String,
    /// STUN/NATMAP-style keep-alive is actively refreshing mappings this session.
    #[serde(default)]
    pub stun_keepalive_active: bool,
    /// Last STUN-discovered public UDP port (0 = unknown).
    #[serde(default)]
    pub public_udp_port: u16,
    /// Last discovered public TCP listen port (0 = unknown / same as local).
    #[serde(default)]
    pub public_tcp_port: u16,
    /// Whether the last TCP mapping hold (reuseaddr connect) succeeded.
    #[serde(default)]
    pub tcp_mapping_hold_ok: bool,
    /// Whether Ember-native (Noise DHT) is enabled — status-bar EmberDHT dot.
    #[serde(default)]
    pub ember_native_enabled: bool,
    /// Live Ember DHT routing-table contacts — status-bar EmberDHT peer count.
    #[serde(default)]
    pub ember_dht_contacts: u32,
    /// Of [`ember_dht_contacts`], those that have answered us. The status bar
    /// and search readiness use this so gossip-only leads do not look like a
    /// joined overlay.
    #[serde(default)]
    pub ember_dht_verified_contacts: u32,
    /// SecIdent RSA key: `"available"`, `"unavailable"` (never had a key),
    /// or `"broken"` (cryptkey.dat exists but could not be read).
    #[serde(default)]
    pub secident_status: String,
}

/// Diagnostic counters for the Ember mesh (EPX, LowID broker). Surfaced
/// via `get_ember_diagnostics`; status-bar gauges (`ember_native_enabled`,
/// `ember_dht_contacts`, `ember_dht_verified_contacts`) also live on
/// `NetworkStats` for the hot poll path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmberDiagnostics {
    /// Source-exchange events accepted from a connected Ember peer this session.
    pub epx_events_received: u32,
    /// Total unique Ember peers tracked in the mesh discovery cache.
    pub ember_peers_known: u32,
    /// LowID broker: peer/server relay attempts scheduled this session.
    pub broker_relay_attempts: u32,
    /// LowID broker: relay connections that reached the transfer path.
    pub broker_relay_successes: u32,
    /// LowID broker: relay failures reported this session.
    pub broker_relay_failures: u32,
    /// LowID broker: connection attempts in flight right now.
    pub broker_active_attempts: u32,
    /// LowID broker: relay-capable peers currently cached as candidates.
    pub broker_relay_candidates: u32,
    /// Age in seconds of the longest-running in-flight broker attempt
    /// (0 when idle) — a stuck attempt surfaces as a growing value.
    pub broker_oldest_attempt_age_secs: u64,
    /// Friend transfers: `OP_EMBER_XFER_REQ`s asking a friend to dial us.
    #[serde(default)]
    pub friend_xfer_connect_back_requested: u32,
    /// Friend transfers: requests asking for a coordinated hole-punch.
    #[serde(default)]
    pub friend_xfer_punch_requested: u32,
    /// Friend transfers: requests a friend accepted.
    #[serde(default)]
    pub friend_xfer_accepted: u32,
    /// Friend transfers: requests a friend declined.
    #[serde(default)]
    pub friend_xfer_declined: u32,
    /// Friend transfers: connections adopted into a waiting download. The only
    /// counter that proves the mechanism worked end to end.
    #[serde(default)]
    pub friend_xfer_connected: u32,
    /// Friend transfers: requests that timed out without a connection.
    #[serde(default)]
    pub friend_xfer_timed_out: u32,
    /// Friend transfers: inbound requests we accepted (we are the uploader).
    #[serde(default)]
    pub friend_xfer_inbound_accepted: u32,
    /// Friend transfers: inbound requests we declined.
    #[serde(default)]
    pub friend_xfer_inbound_declined: u32,
    /// Relay sessions this node is currently bridging for other peers.
    pub relay_sessions_active: u32,
    /// Total bytes this node has relayed for other peers this session
    /// (in-flight sessions plus completed ones).
    pub relay_bytes_relayed: u64,
    /// Whether the Ember-native Noise transport is currently routing
    /// UDP packets (mirrors `AppSettings::ember_native_enabled`).
    pub ember_native_enabled: bool,
    /// Established Noise sessions held by `EmberTransport`.
    pub ember_sessions: u32,
    /// `EmberControlMessage::Ping` packets we sent over the transport
    /// this session. Bumped when `prepare_outgoing` succeeds.
    pub ember_pings_sent: u32,
    /// `EmberControlMessage::Ping` packets we received and replied to.
    pub ember_pings_received: u32,
    /// `EmberControlMessage::Pong` packets we received in response to
    /// a ping we initiated.
    pub ember_pongs_received: u32,
    /// `EmberControlMessage::ExchangeRequest` packets we received and
    /// answered with our current EPX payload over the Noise channel.
    pub ember_exchange_requests_received: u32,
    /// `EmberControlMessage::ExchangeData` payloads we sent over the
    /// Noise channel (replies to a request).
    pub ember_exchange_sent: u32,
    /// `EmberControlMessage::ExchangeData` payloads we received over the
    /// Noise channel and fed into the shared EPX source-ingestion path.
    pub ember_exchange_received: u32,
    /// Local Noise X25519 public key advertised by `EmberTransport`,
    /// hex-encoded. Surfaces here so the harness can dial this node
    /// without needing a separate identity command.
    #[serde(default)]
    pub local_noise_public_key: String,
    /// Our 128-bit Ember DHT node ID (`BLAKE3(ed25519_pub)[..16]`),
    /// hex-encoded. Equal to the `ember_hash`.
    #[serde(default)]
    pub ember_dht_node_id: String,
    /// Our Ed25519 public key, hex-encoded. A peer needs this (plus our
    /// address and Noise key) to seed us into their DHT routing table.
    #[serde(default)]
    pub local_ed25519_public_key: String,
    /// Live contacts in the Ember DHT routing table.
    #[serde(default)]
    pub ember_dht_contacts: u32,
    /// Of the above, contacts that have actually answered us. The rest are
    /// gossip we have been told about and not yet reached, so a table that
    /// looks full while this stays near zero is a node that is not really in
    /// the network — which the total alone cannot show.
    #[serde(default)]
    pub ember_dht_verified_contacts: u32,
    /// Rough size of the whole Ember network, from how tightly the peers we
    /// have proven are packed around our own ID (see
    /// `RoutingTable::estimated_network_size`). Zero while too few have
    /// answered for the density to mean anything. A diagnostic only: it is an
    /// estimate, and a determined peer could skew it.
    #[serde(default)]
    pub ember_dht_estimated_nodes: u32,
    /// Records held for other publishers that are due to be replicated onward
    /// and have not been yet. Persistently above the per-cycle budget means
    /// replication is falling behind, which a republish count cannot show.
    #[serde(default)]
    pub ember_dht_republish_backlog: u32,
    /// Seconds since any Ember DHT frame arrived, or zero if none ever has.
    /// The one number that separates "still joining" from "joined and quiet"
    /// from "stuck", none of which the other counters distinguish.
    #[serde(default)]
    pub ember_dht_seconds_since_inbound: u32,
    /// Ember DHT `PING` frames we sent this session.
    #[serde(default)]
    pub ember_dht_pings_sent: u32,
    /// Ember DHT `PING` frames we received and answered this session.
    #[serde(default)]
    pub ember_dht_pings_received: u32,
    /// Ember DHT `PONG` frames we received in response to our pings.
    #[serde(default)]
    pub ember_dht_pongs_received: u32,
    /// Ember DHT `FIND_NODE` queries we sent this session (includes the
    /// per-hop queries fanned out by iterative lookups).
    #[serde(default)]
    pub ember_dht_find_nodes_sent: u32,
    /// Ember DHT `FIND_NODE` queries we received and answered this session.
    #[serde(default)]
    pub ember_dht_find_nodes_received: u32,
    /// Contact-list replies (`PEER_LIST`) we received this session.
    ///
    /// Paired with [`Self::ember_dht_gossip_contacts`] this separates the two
    /// reasons a table stops growing, which otherwise look identical from
    /// outside: zero replies means our `ANNOUNCE_PEER` is going unanswered,
    /// while replies carrying no contacts means the peers genuinely have
    /// nobody to introduce.
    #[serde(default)]
    pub ember_dht_peer_lists_received: u32,
    /// Contacts carried in inbound gossip (`PEER_LIST`, `FOUND_NODE`,
    /// `ANNOUNCE_PEER`) this session, counted before admission — including
    /// ones we already hold.
    #[serde(default)]
    pub ember_dht_gossip_contacts: u32,
    /// Of those, peers we did not already hold and the table accepted.
    #[serde(default)]
    pub ember_dht_gossip_new: u32,
    /// Of those, ones the table turned away on IP policy or diversity caps.
    #[serde(default)]
    pub ember_dht_gossip_refused: u32,
    /// Iterative Ember DHT lookups currently running (gauge, not a
    /// counter).
    #[serde(default)]
    pub ember_dht_active_searches: u32,
    /// Distinct keys held in the local Ember DHT record store (gauge).
    #[serde(default)]
    pub ember_dht_stored_keys: u32,
    /// Total signed records held in the local Ember DHT store (gauge).
    #[serde(default)]
    pub ember_dht_stored_records: u32,
    /// Of the above, distinct keys holding at least one record authored by
    /// someone other than us — what we're genuinely storing on the
    /// network's behalf, rather than a record of our own that happens to
    /// have landed in our own store (see `EmberDht::foreign_store_stats`).
    #[serde(default)]
    pub ember_dht_stored_for_others_keys: u32,
    /// Of `ember_dht_stored_records`, how many were authored by someone
    /// other than us (see `ember_dht_stored_for_others_keys`).
    #[serde(default)]
    pub ember_dht_stored_for_others_records: u32,
    /// Records we accepted (verified + stored) this session. Counted per
    /// record rather than per frame, since a `STORE_BATCH` carries many.
    #[serde(default)]
    pub ember_dht_stores_received: u32,
    /// `FIND_VALUE` queries we received and answered this session.
    #[serde(default)]
    pub ember_dht_find_values_received: u32,
    /// Keyword/source publishes currently in flight (gauge, not a
    /// counter).
    #[serde(default)]
    pub ember_dht_active_publishes: u32,
    /// Bucket-refresh lookups launched by the maintenance loop this
    /// session (slice 6).
    #[serde(default)]
    pub ember_dht_refreshes: u32,
    /// Maintenance liveness `PING`s sent to stale contacts this session.
    #[serde(default)]
    pub ember_dht_liveness_pings_sent: u32,
    /// Contacts evicted after failing repeated liveness pings this
    /// session.
    #[serde(default)]
    pub ember_dht_contacts_evicted: u32,
    /// Stored records re-published (replicated) to the closest nodes by
    /// the maintenance loop this session.
    #[serde(default)]
    pub ember_dht_records_republished: u32,
    /// KAD-bridge bootstrap `PING`s sent this session (slice 13): while the
    /// DHT table is still sparse, the maintenance loop DHT-pings Ember peers
    /// learned from KAD source publishes so their signed `PONG` folds them
    /// into the routing table. Self-disables once the table is bootstrapped.
    #[serde(default)]
    pub ember_dht_kad_bridge_pings: u32,
    /// Ember DHT *source* records (re)published for our shared files this
    /// session (slice 9): one per STORE attempt fanned out by the publish
    /// tick, so a non-zero value means we are advertising ourselves as a
    /// source on the DHT.
    #[serde(default)]
    pub ember_dht_sources_published: u32,
    /// Ember DHT source lookups started for active/pending downloads this
    /// session (slice 9).
    #[serde(default)]
    pub ember_dht_source_searches: u32,
    /// Verified source records discovered via Ember DHT `FIND_VALUE` for our
    /// downloads this session (slice 9), before dedup/injection filtering.
    #[serde(default)]
    pub ember_dht_source_records_found: u32,
    /// Ember DHT *keyword* records (re)published for our shared files this
    /// session (slice 8): incremented once per file whose keyword records
    /// have all been confirmed stored by a peer.
    #[serde(default)]
    pub ember_dht_keywords_published: u32,
    /// Slice 14: inbound Ember DHT frames dropped by per-IP rate limits.
    #[serde(default)]
    pub ember_dht_rate_limited: u32,
    /// Slice 14: inbound STORE frames rejected as short-window signature replays.
    #[serde(default)]
    pub ember_dht_store_replays: u32,
    /// Slice 15: true when we are LowID/firewalled but still self-publishing
    /// Ember DHT source records (UDP Noise path is usable).
    #[serde(default)]
    pub ember_dht_firewalled_publishing: bool,
    /// True when firewalled with no HighID buddy yet — source STORE is skipped.
    #[serde(default)]
    pub ember_dht_waiting_buddy: bool,
    /// Slice 15: true when Ember is on but we have no external IPv4 to put
    /// in source records (STUN / HighID / KAD have not produced one yet).
    #[serde(default)]
    pub ember_dht_udp_unreachable: bool,
    /// Buddy PROXY_STORE requests we sent this session (firewalled publisher).
    #[serde(default)]
    pub ember_dht_buddy_publishes: u32,
    /// PROXY_STORE requests we accepted and fanned out as a HighID buddy.
    #[serde(default)]
    pub ember_dht_buddy_forwards: u32,
    /// Ember `CALLBACK_REQ` frames we sent (searcher → buddy).
    #[serde(default)]
    pub ember_dht_callback_sent: u32,
    /// `CALLBACK_REQ`s we bounced to a firewalled publisher.
    #[serde(default)]
    pub ember_dht_callback_forwards: u32,
    /// `CALLBACK`s we honoured by connecting back to the searcher.
    #[serde(default)]
    pub ember_dht_callback_connects: u32,
    /// Outbound `FIND_VALUE` frames sent this session (slice 17).
    #[serde(default)]
    pub ember_dht_find_values_sent: u32,
    /// Completed FIND_VALUE searches that gathered at least one record.
    #[serde(default)]
    pub ember_dht_search_hits: u32,
    /// Completed FIND_VALUE searches that returned no records.
    #[serde(default)]
    pub ember_dht_search_misses: u32,
    /// Iterative search rounds that dispatched at least one query.
    #[serde(default)]
    pub ember_dht_search_rounds: u32,
    /// Inbound FIND_VALUE answered with FOUND_VALUE (we held matching records).
    #[serde(default)]
    pub ember_dht_find_value_hits: u32,
    /// Inbound FIND_VALUE answered with FOUND_NODE (miss / continue walk).
    #[serde(default)]
    pub ember_dht_find_value_misses: u32,
    /// Inbound FIND_VALUE answers that could not carry every matching record
    /// this node holds, because one datagram fits only about five. Successive
    /// queries rotate which window is served, so a publisher behind the first
    /// handful is no longer permanently invisible here.
    #[serde(default)]
    pub ember_dht_found_value_truncated: u32,
    /// Records left out of those answers. Read against
    /// `ember_dht_found_value_truncated`: how often the cap binds versus how
    /// much it costs when it does.
    #[serde(default)]
    pub ember_dht_found_value_withheld: u32,
    /// Outbound STORE_ACK receipts (successful remote stores) this session.
    #[serde(default)]
    pub ember_dht_stores_acked: u32,
    /// Outbound STORE targets that failed or timed out this session.
    #[serde(default)]
    pub ember_dht_stores_failed: u32,
    /// Sum of `acked` counts across finished publishes (for avg replication).
    #[serde(default)]
    pub ember_dht_replication_sum: u64,
    /// Finished publish operations this session (denominator for avg replication).
    #[serde(default)]
    pub ember_dht_publishes_completed: u32,
    /// Average STORE replication depth this session (`replication_sum / publishes`).
    #[serde(default)]
    pub ember_dht_avg_replication: u32,
    /// Slice 19: inbound Ember DHT frames rejected as malformed.
    #[serde(default)]
    pub ember_dht_malformed: u32,
    /// Inbound Ember DHT frames refused because the version byte is outside
    /// this build's supported range. Counted separately from `ember_dht_malformed`
    /// so a peer we cannot speak to does not look like packet loss.
    #[serde(default)]
    pub ember_dht_version_mismatch: u32,
    /// Completed KAD lookups of the Ember rendezvous key this session.
    #[serde(default)]
    pub ember_dht_rendezvous_lookups: u32,
    /// How many of those lookups returned no other Ember node after dropping
    /// our own advert. The bootstrap canary: a cold node that keeps drawing
    /// blanks is not going to join.
    #[serde(default)]
    pub ember_dht_rendezvous_empty: u32,
    /// Advertised Ember nodes in the most recent rendezvous lookup, after
    /// dropping self. A gauge, not a counter.
    #[serde(default)]
    pub ember_dht_rendezvous_last_peers: u32,
    /// Slice 19: observed-IP votes recorded from PONG payloads.
    #[serde(default)]
    pub ember_dht_observed_votes: u32,
    /// Slice 19: confirmed observed external address (`ip:port`), if any.
    #[serde(default)]
    pub ember_dht_observed_addr: String,
    /// Shared files that have a confirmed Ember DHT *source* record right
    /// now. Unlike the session counters above this falls again when a file is
    /// unshared or the overlay is switched off, so it is what the UI should
    /// use to answer "can other people find my files". It is also the exact
    /// set behind the Library's Ember badge, so the two cannot disagree.
    #[serde(default)]
    pub ember_dht_published_files: u32,
    /// Every source listed in an EPX payload we accepted, before any
    /// filtering. The denominator for EPX yield: compare against
    /// `NetworkStats::epx_sources_received`, which counts only the sources
    /// that reached a live download. A large gap means we are spending
    /// bandwidth on exchanges that tell us nothing.
    #[serde(default)]
    pub epx_sources_offered: u32,
    /// EPX sources for a file we *are* downloading that were still dropped —
    /// IP-filtered, banned, known-dead, or an unreachable LowID peer. Distinct
    /// from the much larger set we skip because the file is not ours: this
    /// counts sources a peer thought were worth sending and we judged unusable,
    /// so a peer feeding us junk shows up here rather than silently.
    #[serde(default)]
    pub epx_sources_filtered: u32,
    /// UDP EPX replies dropped before sending because the payload could not
    /// fit one Ember datagram. The TCP builder has no per-datagram ceiling and
    /// there is no fragmentation here, so on a node with a busy download list
    /// this can be *every* reply — a silent no-op that otherwise looks
    /// identical to having no peers ask.
    #[serde(default)]
    pub epx_udp_oversized_skipped: u32,
    /// Inbound DHT records refused because the store is holding its maximum
    /// number of distinct keys. Unlike the byte budget there is no eviction
    /// here, so a sustained count means new keys — including ones this node is
    /// genuinely closest to — are being turned away.
    #[serde(default)]
    pub ember_dht_store_key_cap_rejections: u32,
    /// STORE frames whose publisher signature did not parse, or whose DHT
    /// key did not match the record's own content key.
    #[serde(default)]
    pub ember_dht_store_reject_verify: u32,
    /// STORE frames refused because the Ed25519 signature did not verify.
    #[serde(default)]
    pub ember_dht_store_reject_signature: u32,
    /// STORE frames refused because the signed creation time was too far
    /// in the future or already past TTL.
    #[serde(default)]
    pub ember_dht_store_reject_timestamp: u32,
    /// Source records refused by the per-IP cap.
    #[serde(default)]
    pub ember_dht_store_reject_source_ip_cap: u32,
    /// Records refused because one publisher already holds its share of the key.
    #[serde(default)]
    pub ember_dht_store_reject_publisher_cap: u32,
    /// Records refused because the key already holds `MAX_RECORDS_PER_KEY`.
    #[serde(default)]
    pub ember_dht_store_reject_per_key_cap: u32,
    /// Source records whose declared IP did not match the Noise sender.
    #[serde(default)]
    pub ember_dht_store_reject_source_ip: u32,
    /// STORE records for keys this node is not close enough to hold.
    #[serde(default)]
    pub ember_dht_store_reject_proximity: u32,
    /// Completed FIND_VALUE searches this session (hits, misses, and timeouts).
    /// Denominator for the search-quality averages below.
    #[serde(default)]
    pub ember_dht_search_outcomes: u32,
    /// Sum of shortlist nodes that answered across those searches.
    #[serde(default)]
    pub ember_dht_search_nodes_answered: u64,
    /// Sum of FIND_VALUE durations in milliseconds.
    #[serde(default)]
    pub ember_dht_search_elapsed_ms_sum: u64,
    /// Sum of verified records gathered across those searches.
    #[serde(default)]
    pub ember_dht_search_records_sum: u64,
    /// Highest verified-contact count seen today (UTC), persisted across restart.
    #[serde(default)]
    pub ember_dht_verified_highwater_today: u32,
    /// Highest verified-contact count ever recorded on this node.
    #[serde(default)]
    pub ember_dht_verified_highwater: u32,
}

/// Serializable KAD contact info for the frontend (mirrors eMule KadContactListCtrl columns)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KadContactInfo {
    pub id: String,
    #[serde(rename = "type")]
    pub contact_type: u8,
    pub version: u8,
    pub distance: String,
    pub ip_verified: bool,
    pub bootstrap: bool,
}

/// Serializable KAD search entry for the frontend (mirrors eMule KadSearchListCtrl columns)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KadSearchInfo {
    pub id: u64,
    pub target: String,
    #[serde(rename = "type")]
    pub search_type: String,
    pub name: String,
    pub status: String,
    pub load: u32,
    pub load_response: u32,
    pub load_total: u32,
    pub packets_sent: u32,
    pub request_answer: u32,
    pub responses: u32,
    /// K30: unix timestamp (seconds) when the search was created. The
    /// UI derives an "age" column from this so users can see if a
    /// search is fresh or stuck.
    pub started_at: i64,
}

impl Default for NetworkStats {
    fn default() -> Self {
        Self {
            connected_peers: 0,
            upload_speed: 0,
            download_speed: 0,
            total_uploaded: 0,
            total_downloaded: 0,
            status: NetworkStatus::Disconnected,
            external_ip: String::new(),
            firewalled: false,
            buddy_status: String::from("none"),
            upnp_mapped: false,
            stores_acknowledged: 0,
            kad_users_estimate: 0,
            tcp_status: String::from("Unknown"),
            udp_status: String::from("Unknown"),
            nat_type: String::from("Unknown"),
            ember_peers: 0,
            epx_sources_received: 0,
            server_status: String::from("disconnected"),
            stun_keepalive_active: false,
            public_udp_port: 0,
            public_tcp_port: 0,
            tcp_mapping_hold_ok: false,
            ember_native_enabled: true,
            ember_dht_contacts: 0,
            ember_dht_verified_contacts: 0,
            secident_status: String::from("unavailable"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkStatus {
    Connected,
    Connecting,
    Disconnected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
// Do not use `deny_unknown_fields`: a config.json written by a newer Ember
// build (extra keys) must still load on downgrade. Unknown keys are ignored;
// missing known fields use `#[serde(default)]` / field defaults where set.
// Completely unreadable JSON still falls back to defaults after backup.
pub struct AppSettings {
    pub nickname: String,
    pub shared_folders: Vec<String>,
    pub download_folder: String,
    pub max_upload_speed: u64,
    pub max_download_speed: u64,
    pub max_concurrent_downloads: u32,
    #[serde(default = "default_max_uploads")]
    pub max_concurrent_uploads: u32,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub nodes_dat_path: String,
    pub upnp_enabled: bool,
    /// Keep full-cone / CGNAT port mappings alive with STUN (and a TCP
    /// hold from the listen port), and advertise the discovered public
    /// ports for HighID. Safe no-op on open/UPnP networks; disable if
    /// outbound STUN is blocked on your network.
    #[serde(default = "default_true")]
    pub stun_keepalive_enabled: bool,
    /// Prefer obfuscated (encrypted) KAD communication when the peer supports it
    #[serde(default = "default_true")]
    pub obfuscation_enabled: bool,
    /// Enable IP filter to block known-bad IP ranges (loads ipfilter.dat)
    #[serde(default = "default_true")]
    pub ip_filter_enabled: bool,
    /// Apply IP filter ranges / private blocking to incoming TCP upload
    /// connections only. Off by default: VPN IPs commonly appear in
    /// ipfilter.dat "hosting" ranges, silently breaking connectivity for
    /// a large portion of users. Kad and eD2K UDP still always consult the
    /// list. Outbound filtering still applies, and the abuse tracker / ban
    /// list protect against misbehaving inbound peers. Truly-unroutable
    /// "bogus" IPs (loopback, multicast, documentation, class-E, …) are
    /// always rejected inbound regardless of this toggle.
    #[serde(default)]
    pub filter_incoming_connections: bool,
    /// Answer standard ed2k "View Files" requests (`OP_ASKSHAREDFILES`) from
    /// any peer — eMule, aMule, MLDonkey, or any other compatible client —
    /// with our real shared-file list (`OP_ASKSHAREDFILESANSWER`). This is
    /// the classic eDonkey2000/eMule "browse shared files" feature; it is
    /// unrelated to the Ember-only friend browse feature
    /// (`friend_browse_disabled`), which uses a separate, authenticated
    /// mechanism. Off by default: exposing your file list to any anonymous
    /// peer is a new capability, not a restriction on an existing one, so
    /// it must be explicitly opted into. When off, requests get a polite
    /// `OP_ASKSHAREDDENIEDANS` refusal rather than being silently dropped,
    /// matching real eMule's "deny" behavior.
    #[serde(default)]
    pub allow_shared_files_browse: bool,
    /// Block private/LAN/CGNAT IPs across KAD contact admission, outbound
    /// dials, UDP ingest, and (when filter-incoming is on) inbound TCP.
    /// Bogus/unroutable space is always rejected regardless of this toggle.
    #[serde(default = "default_true")]
    pub block_private_ips: bool,
    /// Also apply IP filter to ed2k servers (eMule: "Filter servers by IP")
    #[serde(default = "default_true")]
    pub filter_servers_by_ip: bool,
    /// Accept new servers from connected server's OP_SERVERLIST (eMule: "Update server list when connecting")
    #[serde(default = "default_true")]
    pub add_servers_from_server: bool,
    /// Accept new servers from ed2k clients (eMule: "Update server list from clients")
    #[serde(default = "default_true")]
    pub add_servers_from_clients: bool,
    /// Path to server.met file for ed2k server list
    #[serde(default)]
    pub server_list_path: String,
    /// Automatically connect to KAD on startup (eMule: "Autoconnect" for Kad)
    #[serde(default)]
    pub auto_connect_kad: bool,
    /// Automatically connect to an ed2k server on startup (eMule: "Autoconnect" for server),
    /// independent of `auto_connect_kad`. Defaults to `false`. KAD Connect never
    /// starts an eD2K session — use the Servers page or enable this setting.
    #[serde(default)]
    pub auto_connect_server: bool,
    /// Maximum sources tracked per file (eMule: maxsourceperfile, default 400)
    #[serde(default = "default_max_sources_per_file")]
    pub max_sources_per_file: u32,
    /// Maximum total TCP connections (eMule: maxconnections, default 500)
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Add new downloads in paused state (eMule: addnewfilespaused)
    #[serde(default)]
    pub add_downloads_paused: bool,
    /// Automatically remove completed downloads from the list
    #[serde(default)]
    pub remove_finished_downloads: bool,
    /// Globally prioritize the first and last part of every download so media
    /// files become previewable as early as possible (eMule's global "preview
    /// priority" preference). When on, every transfer behaves as if its
    /// per-file preview-priority toggle were enabled, without mutating that
    /// per-file flag. Off by default (rarest-first is best for swarm health).
    #[serde(default)]
    pub preview_priority_all: bool,
    /// Skip compressing video files during upload (eMule: dontcompressavi)
    #[serde(default)]
    pub skip_compress_video: bool,
    /// Enable the AntiLeech client-software filter. Pattern list lives in
    /// `<data_dir>/antileech.dat` and is loaded at startup; toggling this
    /// at runtime is supported via the `set_antileech_enabled` Tauri
    /// command. Off by default — opt-in to avoid surprising regressions
    /// for users who didn't ask to filter peers. Matching uses the
    /// rendered software label plus the peer's mod tag.
    #[serde(default)]
    pub antileech_enabled: bool,
    /// Upload Speed Sense: dynamically adjust upload limit based on network latency
    #[serde(default)]
    pub uss_enabled: bool,
    /// Pipe-separated substrings to remove from filenames for display cleanup
    #[serde(default = "default_filename_cleanups")]
    pub filename_cleanups: String,
    /// Enable the search spam filter (eMule-compatible multi-signal scoring)
    #[serde(default = "default_true")]
    pub spam_filter_enabled: bool,
    /// Search spam profile: `balanced` (default) or `aggressive`
    #[serde(default = "default_spam_filter_profile")]
    pub spam_filter_profile: String,
    /// Max time (seconds) to wait in remote upload queue before giving up (eMule-style; default 1800)
    #[serde(default = "default_download_queue_wait_secs")]
    pub download_queue_wait_secs: u64,
    /// Extra multi-source retry rounds after initial source tasks (default 3)
    #[serde(default = "default_multisource_retry_rounds")]
    pub multisource_retry_rounds: u32,
    /// Per-source part hash failure retry rounds during data transfer (default 3)
    #[serde(default = "default_download_part_retry_rounds")]
    pub download_part_retry_rounds: u32,
    /// Maximum download file size in GiB (1–593; default 593 — the ed2k
    /// part-count ceiling, see `ed2k_download_limits`)
    #[serde(default = "default_max_download_file_size_gib")]
    pub max_download_file_size_gib: u32,
    /// Max seconds to wait for a keyword/global search to finish (30–600; default 120).
    #[serde(default = "default_search_timeout_secs")]
    pub search_timeout_secs: u64,
    /// When false, the UI stops persisting recent search queries (the search
    /// history dropdown) to local storage. Frontend-only behavior — the backend
    /// just round-trips it. Defaults to true so existing users keep the prior
    /// "history is saved" behavior.
    #[serde(default = "default_true")]
    pub save_search_history: bool,
    /// Whether the first-time setup wizard has been completed
    #[serde(default)]
    pub setup_complete: bool,
    /// Internal migration marker: the default Downloads share has already
    /// been considered. Once true, startup must not recreate a folder the
    /// user subsequently removed.
    #[serde(default)]
    pub default_shared_folder_seeded: bool,
    /// Monotonic optimistic-concurrency token for whole-settings saves.
    #[serde(default)]
    pub settings_revision: u64,

    /// Require approval before granting friend-slot priority to new friend requests
    #[serde(default = "default_true")]
    pub friend_require_approval: bool,
    /// Disable incoming chat messages from friends
    #[serde(default)]
    pub friend_chat_disabled: bool,
    /// Disable browse-shares responses to friends
    #[serde(default)]
    pub friend_browse_disabled: bool,
    /// Maximum number of friends allowed (1–500, default 200)
    #[serde(default = "default_max_friends")]
    pub max_friends: u32,
    /// Encrypt friend sessions with RC4 obfuscation (default true)
    #[serde(default = "default_true")]
    pub friend_session_encryption: bool,
    /// Rendezvous server URL for friend discovery
    #[serde(default = "default_rendezvous_url")]
    pub rendezvous_url: String,
    /// Join the Ember-native Noise-encrypted overlay — the UDP transport and
    /// the Kademlia DHT — alongside the existing eMule KAD/eD2K stack.
    ///
    /// **Always on.** The DHT has no central bootstrap: a node finds its
    /// first contacts through the KAD bridge, peer exchange, DHT gossip, and
    /// its persisted contact file, so the overlay only works when ordinary
    /// clients take part in it. The Settings and Ember-page switches stay
    /// visible but cannot turn this off.
    ///
    /// See [`Self::ember_default_on_migrated`] for how upgrades from the
    /// opt-in era are handled.
    #[serde(default = "default_true")]
    pub ember_native_enabled: bool,
    /// One-shot marker for the upgrade that made [`Self::ember_native_enabled`]
    /// default to on (and later, always on).
    ///
    /// Every config written while the overlay was opt-in stores an explicit
    /// `false` that records the old default rather than a preference, so the
    /// loader flips those once and sets this. A later stored `false` is also
    /// turned back on: the overlay can no longer be disabled.
    ///
    /// Backend-owned (see `BACKEND_OWNED_SETTINGS_FIELDS`): letting the
    /// renderer clear it would re-run the migration.
    #[serde(default)]
    pub ember_default_on_migrated: bool,
    /// Whether this node will carry relay traffic for other peers.
    ///
    /// Relaying was previously implicit: any node with a public address and a
    /// bound QUIC port self-signed an attestation and advertised it, with no
    /// way to decline. That was tolerable while attestations only travelled
    /// within a file swarm, but they are now forwarded between friends, so a
    /// reachable node can be asked to relay for pairs it never traded with.
    /// Defaults to on — relaying is what makes symmetric-NAT pairs work at all
    /// — but is now a choice rather than an assumption.
    #[serde(default = "default_relay_for_peers")]
    pub relay_for_peers: bool,
    /// Ceiling on concurrent relay sessions carried for other peers. Bounds
    /// the uplink a generous node donates; `0` is treated as "use the default"
    /// rather than "relay nothing", which [`Self::relay_for_peers`] expresses.
    #[serde(default = "default_max_relay_sessions")]
    pub max_relay_sessions: u32,
    /// What to do when the user closes the main window via the title-bar X.
    ///
    /// - `"ask"` (default): emit a dialog asking the user to choose.
    /// - `"tray"`: hide the window to the system tray; the app keeps
    ///   running and seeding/downloading in the background.
    /// - `"exit"`: fully quit the application as if the user picked
    ///   File → Exit.
    ///
    /// Stored as a string (not an enum) to mirror `spam_filter_profile`
    /// — easier to extend later without breaking deserialization for
    /// users on older configs.
    #[serde(default = "default_close_to_tray_behavior")]
    pub close_to_tray_behavior: String,
    /// Maximize the main window when Ember launches.
    ///
    /// The window is created at its configured size (see `tauri.conf.json`)
    /// and maximized during startup when this is set — it's a launch-time
    /// preference, not a live toggle, so changing it only takes effect on
    /// the next launch. Off by default.
    ///
    /// `alias = "launch_fullscreen"` accepts this field's former name (shipped
    /// in an intermediate build) so an existing `config.json` still maps the
    /// old key onto `launch_maximized`. Without the alias the legacy key would
    /// be ignored as unknown and the preference would silently reset to the
    /// default. The old boolean carries over unchanged; the canonical name is
    /// written back on the next save.
    #[serde(default, alias = "launch_fullscreen")]
    pub launch_maximized: bool,
    /// Per-shared-folder default upload priority (eMule: directory priority).
    /// Maps a shared folder path to one of the priority strings
    /// (`verylow`/`low`/`normal`/`high`/`release`/`auto`). Files discovered
    /// under a folder adopt its priority unless individually overridden.
    #[serde(default)]
    pub folder_priorities: std::collections::HashMap<String, String>,
    /// Explicit share choices made for files that were still hashing. Keys are
    /// normalized paths; values are applied before their first hash completes
    /// so an unshare action survives an app restart.
    #[serde(default)]
    pub pending_share_states: std::collections::HashMap<String, bool>,
    /// Explicit priorities made for files that were still hashing. Kept
    /// separately from folder defaults because an explicit action must win.
    #[serde(default)]
    pub pending_file_priorities: std::collections::HashMap<String, String>,
    /// Resume keys for bounded shared-folder discovery pages. Each normalized
    /// folder path advances only after its page has been committed, so folders
    /// larger than the in-memory scan budget are eventually indexed in full.
    #[serde(default)]
    pub shared_folder_scan_cursors: std::collections::HashMap<String, String>,
    /// Automatically check for Ember updates in the background shortly
    /// after launch (subject to `update_check_frequency`). This only gates
    /// the *silent* startup check — the "Check for Updates" button in
    /// Settings → About always works regardless of this setting. Defaults
    /// to `true` to preserve Ember's original always-check-on-launch
    /// behavior for existing users upgrading into this setting.
    #[serde(default = "default_true")]
    pub auto_check_updates: bool,
    /// How often the automatic background check gated by `auto_check_updates`
    /// may run: `"daily"`, `"weekly"`, or `"monthly"`. This is only the
    /// user's preference — the actual "was it long enough ago?" bookkeeping
    /// (last-checked timestamp) is tracked on the frontend
    /// (`src/lib/stores/updater.ts`), since the whole update-check flow
    /// already lives there with no backend involvement.
    #[serde(default = "default_update_check_frequency")]
    pub update_check_frequency: String,
}

/// Sanitized ed2k download limits derived from [`AppSettings`] (clamped for safety).
#[derive(Clone, Copy, Debug)]
pub struct Ed2kDownloadLimits {
    pub queue_wait_secs: u64,
    pub multisource_retry_rounds: u32,
    pub part_retry_rounds: u32,
    pub max_download_bytes: u64,
}

impl AppSettings {
    pub fn ed2k_download_limits(&self) -> Ed2kDownloadLimits {
        // Standard ED2K wire part counts are u16. The integer GiB setting is
        // capped at 593, then the exact byte ceiling closes the remaining
        // fractional-GiB gap so malformed settings cannot reintroduce wraps.
        let gib = self.max_download_file_size_gib.clamp(1, 593) as u128;
        let max_download_bytes = (gib.saturating_mul(1024 * 1024 * 1024))
            .min(crate::network::ed2k::messages::ED2K_MAX_FILE_SIZE_BYTES as u128)
            as u64;
        Ed2kDownloadLimits {
            queue_wait_secs: self.download_queue_wait_secs.clamp(60, 14400),
            multisource_retry_rounds: self.multisource_retry_rounds.clamp(1, 20),
            part_retry_rounds: self.download_part_retry_rounds.clamp(1, 20),
            max_download_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub ip: String,
    pub port: u16,
    pub name: String,
    pub description: String,
    pub user_count: u32,
    pub file_count: u32,
    pub max_users: u32,
    pub soft_files: u32,
    pub hard_files: u32,
    pub is_static: bool,
    pub fail_count: u32,
    #[serde(default)]
    pub client_id: u32,
    #[serde(default)]
    pub is_low_id: bool,
}

/// Snapshot of the AntiLeech filter for the Settings UI. Carries the
/// raw pattern list (so the user can edit it verbatim), the
/// enabled-flag, and the resolved on-disk file path so the UI can show
/// "the file you're editing lives at …" for users who want to manage
/// the list externally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiLeechSnapshot {
    pub enabled: bool,
    pub patterns: Vec<String>,
    pub file_path: String,
    pub pattern_count: u32,
}

/// Result of `set_antileech_patterns`. The backend accepts the new
/// list as much as it can — patterns that fail to compile are
/// reported here per-row instead of failing the whole replacement, so
/// a user can fix typos one at a time without losing the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiLeechReplaceResult {
    pub snapshot: AntiLeechSnapshot,
    /// `(pattern, error_message)` pairs for any patterns the regex
    /// engine refused to compile.
    pub compile_errors: Vec<(String, String)>,
}

/// One row in the upload-pane "Queued" tab — a peer that has joined our
/// upload queue but doesn't currently hold a slot. Snapshot taken on
/// demand from `UploadQueueRef`; `wait_seconds` is computed at snapshot
/// time so the UI doesn't need access to monotonic `Instant`s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadQueueClient {
    /// 32-char hex ed2k user hash, or empty when the peer didn't
    /// advertise one (queue identity falls back to IP in that case).
    pub user_hash: String,
    pub peer_ip: String,
    pub peer_port: u16,
    pub file_hash: String,
    pub file_name: String,
    pub wait_seconds: u64,
    /// 1-based queue rank computed via the eMule scoring rules
    /// (`compute_queue_rank` in the upload module). `None` when the
    /// peer is currently disconnected and only `m_bAddNextConnect` is
    /// keeping their slot warm.
    pub queue_rank: Option<u32>,
    /// SecIdent credit ratio (1.0–10.0). 1.0 for first-time peers.
    pub credit_ratio: f64,
    /// Lifetime bytes we have uploaded TO this peer across all sessions.
    pub uploaded: u64,
    /// Lifetime bytes we have downloaded FROM this peer across all sessions.
    pub downloaded: u64,
    /// "Verified" | "Failed" | "Unknown" | "BadGuy" | "Needed"
    pub ident_state: String,
    /// ISO 3166-1 alpha-2 country code, geoip-resolved from `peer_ip`.
    pub country_code: Option<String>,
    pub is_friend: bool,
    /// Raw eMule version byte (Hello CT_EMULE_VERSION). Surfaces in the UI
    /// as a tooltip / column for diagnosing legacy-client penalties.
    pub emule_version: u8,
}

/// One row in the upload-pane "Known Clients" tab — a SecIdent credit
/// record. These are persistent across sessions (clients.met) so the
/// list is the lifetime view of every peer we've ever traded credit
/// with, not just currently-connected peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownClient {
    /// 32-char hex ed2k user hash.
    pub user_hash: String,
    /// Bytes WE downloaded from them across all sessions (eMule's
    /// `m_nDownloaded`). This is the value that buys us upload-queue
    /// priority on their side.
    pub downloaded: u64,
    /// Bytes WE uploaded to them across all sessions (`m_nUploaded`).
    pub uploaded: u64,
    /// Cached `get_score_ratio` for the IP we last identified them at.
    pub credit_ratio: f64,
    /// Unix epoch seconds; the freshest of the per-session timestamps.
    pub last_seen: i64,
    /// "Verified" | "Failed" | "Unknown" | "BadGuy" | "Needed"
    pub ident_state: String,
    /// Best-known peer IPv4/IPv6 string for display, or `None` when unknown.
    /// Prefer SecIdent `ident_ip` when present; otherwise may be filled from
    /// the friends table (`last_ip`) for Ember friends that have no verified
    /// credit IP yet — that path is observed/friend-seen, not SecIdent.
    pub last_known_ip: Option<String>,
    /// ISO 3166-1 alpha-2, geoip-resolved from `last_known_ip`.
    pub country_code: Option<String>,
    /// True iff we have their RSA public key cached (a prerequisite for
    /// Verified state — useful for diagnosing why a record is stuck at
    /// Unknown after several connections).
    pub has_public_key: bool,
    /// Ember node id hex when known (from a verified hello binding).
    /// Friends are keyed by this hash, not `user_hash`.
    pub ember_hash: Option<String>,
    /// True when `ember_hash` is present in the local friends set.
    pub is_friend: bool,
    /// Friend nickname from the friends DB when this row's Ember hash
    /// matches a friends entry (empty otherwise). Surfaced so Known
    /// Clients can show a readable name even with no transfer history.
    #[serde(default)]
    pub nickname: String,
}

fn default_max_uploads() -> u32 {
    5
}

fn default_max_sources_per_file() -> u32 {
    400
}

fn default_max_connections() -> u32 {
    500
}

fn default_download_queue_wait_secs() -> u64 {
    1800
}

fn default_multisource_retry_rounds() -> u32 {
    3
}

fn default_download_part_retry_rounds() -> u32 {
    3
}

fn default_max_download_file_size_gib() -> u32 {
    593
}

fn default_search_timeout_secs() -> u64 {
    120
}

fn default_max_friends() -> u32 {
    200
}

/// Default rendezvous server URL.
///
/// L13: trust model for the V1 default rendezvous host.
///
/// The rendezvous server's role is narrow: it stores
/// `(ember_id, ip, port, pubkey)` tuples that other Ember nodes
/// can look up to find each other when KAD doesn't know the peer.
/// It can NOT impersonate a friend on the data plane — every
/// friend session does its own Ed25519 proof-of-possession before
/// accepting chat, browse, or files (`friend_connect.rs`,
/// `ember_auth.rs`). It can NOT silently rewrite a friend's
/// address to attacker infrastructure either: after C4 the client
/// signs the (id, port, ipv4, pubkey, ts) tuple with the node's
/// Ed25519 secret, the server pins the pubkey to the id on first
/// register, and the lookup endpoint refuses to hand back loopback,
/// link-local, private, or unspecified IPv4 addresses. The HTTPS
/// transport is also pinned by the client (`require_https` +
/// `https_only(true)` in `network/rendezvous.rs::client`), so a
/// network-position attacker between the user and the rendezvous
/// edge cannot rewrite responses without breaking TLS.
///
/// What the rendezvous operator CAN still do:
///   1. **Refuse to answer.** The lookup just returns "no peer found"
///      and the friend stays unreachable until KAD or a cached IP
///      bridges them. This is a denial-of-service, not a confidentiality
///      or integrity issue.
///   2. **Selectively delay queries** to give an attacker time to set
///      up infrastructure at a *new* IP that the real peer is about
///      to register from. The signature still has to verify, so this
///      requires the operator to also be the keypair holder — which
///      means the attacker is impersonating the friend, not the
///      rendezvous, and the user already has a problem the rendezvous
///      can't make worse.
///   3. **Decline future protocol changes** that would tighten the
///      contract further (e.g. signed lookup nonces in V2).
///
/// What it CANNOT do:
///   - Steer chat, browse, or file traffic to an attacker. Every data
///     channel does PoP after the dial.
///   - Impersonate the keypair holder. The pubkey-pin gate forces every
///     post-first registration to come from the same private key.
///   - Inflate or backdate `last_seen` in a way the friend's UI honours.
///     The UI sources liveness from the live session, not the lookup.
///
/// Operators who want to run their own rendezvous can change this URL
/// in Settings; the rest of the stack treats the URL as configuration,
/// not as a trust anchor. Mirror this string in
/// `rendezvous-server/README.md` if you change the default.
pub(crate) fn default_rendezvous_url() -> String {
    "https://ember-rendezvous.fly.dev".to_string()
}

fn default_spam_filter_profile() -> String {
    "balanced".to_string()
}

fn default_relay_for_peers() -> bool {
    true
}

/// Matches the relay manager's historical hard-coded ceiling, so an existing
/// install behaves identically until the user changes it.
fn default_max_relay_sessions() -> u32 {
    4
}

fn default_close_to_tray_behavior() -> String {
    "ask".to_string()
}

fn default_update_check_frequency() -> String {
    "daily".to_string()
}

/// Fresh-install download root: `Downloads/Ember` under the user's known
/// downloads directory, or `~/Downloads/Ember` when that XDG path is unset.
///
/// Never fall back to `std::env::temp_dir()`. On Linux that is `/tmp`, and on
/// Windows it is typically under `AppData\Local\Temp` — both have a basename
/// in `SENSITIVE_DIR_NAMES`, so `validate_settings` would reject the defaults
/// and config load would reset in a loop. Linux CI and servers often have no
/// `xdg-user-dirs` setup, so `UserDirs::download_dir()` is `None` there.
fn default_download_folder() -> String {
    if let Some(user_dirs) = directories::UserDirs::new() {
        if let Some(downloads) = user_dirs.download_dir() {
            return downloads.join("Ember").to_string_lossy().into_owned();
        }
        return user_dirs
            .home_dir()
            .join("Downloads")
            .join("Ember")
            .to_string_lossy()
            .into_owned();
    }
    let home = std::env::var_os(if cfg!(windows) {
        "USERPROFILE"
    } else {
        "HOME"
    })
    .filter(|value| !value.is_empty())
    .map(std::path::PathBuf::from);
    if let Some(home) = home {
        return home
            .join("Downloads")
            .join("Ember")
            .to_string_lossy()
            .into_owned();
    }
    String::new()
}

impl Default for AppSettings {
    fn default() -> Self {
        let download_dir = default_download_folder();

        let completed_dir = std::path::PathBuf::from(&download_dir)
            .join("Downloads")
            .to_string_lossy()
            .to_string();

        Self {
            nickname: format!("Ember-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            shared_folders: vec![completed_dir],
            download_folder: download_dir,
            max_upload_speed: 0,
            max_download_speed: 0,
            max_concurrent_downloads: 5,
            max_concurrent_uploads: 5,
            tcp_port: DEFAULT_TCP_PORT,
            udp_port: DEFAULT_UDP_PORT,
            folder_priorities: std::collections::HashMap::new(),
            pending_share_states: std::collections::HashMap::new(),
            pending_file_priorities: std::collections::HashMap::new(),
            shared_folder_scan_cursors: std::collections::HashMap::new(),
            nodes_dat_path: String::new(),
            upnp_enabled: false,
            stun_keepalive_enabled: true,
            obfuscation_enabled: true,
            ip_filter_enabled: true,
            filter_incoming_connections: false,
            allow_shared_files_browse: false,
            block_private_ips: true,
            filter_servers_by_ip: true,
            add_servers_from_server: true,
            add_servers_from_clients: true,
            server_list_path: String::new(),
            auto_connect_kad: false,
            // Matches `auto_connect_kad`: a fresh launch shouldn't reach out
            // to any network on its own. This used to default to `true`
            // here while `#[serde(default)]` (used once a settings.json
            // already exists but predates this field) fell back to
            // `bool::default() == false` — two different defaults for the
            // same field depending on whether this is a brand-new install
            // or an upgrade. Connecting to a server is real, visible network
            // activity (see `NetworkState::upload_disconnected`), so it must
            // not happen before the user asks for it either way.
            auto_connect_server: false,
            max_sources_per_file: 400,
            max_connections: 500,
            add_downloads_paused: false,
            remove_finished_downloads: false,
            preview_priority_all: false,
            skip_compress_video: false,
            antileech_enabled: false,
            uss_enabled: false,
            filename_cleanups: default_filename_cleanups(),
            spam_filter_enabled: true,
            spam_filter_profile: default_spam_filter_profile(),
            download_queue_wait_secs: default_download_queue_wait_secs(),
            multisource_retry_rounds: default_multisource_retry_rounds(),
            download_part_retry_rounds: default_download_part_retry_rounds(),
            max_download_file_size_gib: default_max_download_file_size_gib(),
            search_timeout_secs: default_search_timeout_secs(),
            save_search_history: true,
            setup_complete: false,
            default_shared_folder_seeded: false,
            settings_revision: 0,
            friend_require_approval: true,
            friend_chat_disabled: false,
            friend_browse_disabled: false,
            friend_session_encryption: true,
            max_friends: default_max_friends(),
            rendezvous_url: default_rendezvous_url(),
            ember_native_enabled: true,
            // A fresh profile already starts on, so there is nothing for the
            // upgrade migration to do.
            ember_default_on_migrated: true,
            relay_for_peers: default_relay_for_peers(),
            max_relay_sessions: default_max_relay_sessions(),
            close_to_tray_behavior: default_close_to_tray_behavior(),
            launch_maximized: false,
            auto_check_updates: true,
            update_check_frequency: default_update_check_frequency(),
        }
    }
}

// -------------------------------------------------------------------------
// Typed event payloads
//
// These mirror the shapes previously built ad-hoc with `serde_json::json!`
// for the very highest-frequency `app_handle.emit(...)` sites — per-block
// download and upload progress. `serde_json::json!` builds a tagged
// `serde_json::Value` tree (one Box/HashMap allocation per field, plus the
// string keys) which Tauri then re-serialises to JSON for the webview.
// With typed structs the JSON is emitted in a single serde pass and field
// keys are known statically, so these events allocate much less under load.
//
// Field names use `camelCase`-free snake_case to match the existing JSON
// keys on the frontend (see `src/lib/stores/transfers.ts`); renaming would
// be a behavioural change.
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct TransferProgressPayload<'a> {
    pub id: &'a str,
    pub downloaded: u64,
    pub total: u64,
    pub progress: f64,
    pub speed: u64,
    /// Only populated for upload-direction events so existing frontend
    /// consumers (`payload.uploaded ?? payload.downloaded`) keep working.
    /// Session wire bytes; may exceed [`total`](Self::total) on uploads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uploaded: Option<u64>,
    /// Upload-direction only: unique per-part coverage this session.
    /// Drives the small-file progress fill (files with too few ED2K parts
    /// for the chunked bar). The chunked bar's overlay is served-parts /
    /// part-count, not this figure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_size: Option<u64>,
    /// `"upload"` for upload progress events; omitted for downloads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_time: Option<u64>,
    /// Upload-direction only: see [`Transfer::up_part_status`]. Carried
    /// on live progress events so the parts bar animates between polls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_part_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_part_count: Option<u32>,
    /// Upload-direction only: see [`Transfer::up_peer_part_status`]. Carried on
    /// live progress events so the dark peer-has shading stays in sync between
    /// the 3 s polls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_peer_part_status: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferSourcesPayload<'a> {
    pub id: &'a str,
    pub sources: u32,
    pub active_sources: u32,
    pub queued_sources: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Configs from a newer build may include unknown keys. Those must be
    /// ignored on downgrade rather than failing deserialize (which would
    /// wipe settings). This guards against reintroducing `deny_unknown_fields`.
    #[test]
    fn unknown_settings_keys_are_ignored() {
        let mut value =
            serde_json::to_value(AppSettings::default()).expect("serialize default settings");
        value
            .as_object_mut()
            .expect("AppSettings serializes to a JSON object")
            .insert(
                "future_setting_from_newer_build".to_string(),
                serde_json::json!(true),
            );
        let parsed: AppSettings = serde_json::from_value(value)
            .expect("unknown keys must not fail AppSettings deserialize");
        assert!(!parsed.nickname.is_empty());
    }

    /// A `config.json` written by the intermediate build stores the launch
    /// preference under the old key `launch_fullscreen`. The serde alias must
    /// map that key onto `launch_maximized` — otherwise the legacy key is
    /// ignored and the preference silently resets to the default. This guards
    /// the rename so the migration can't regress.
    #[test]
    fn legacy_launch_fullscreen_key_maps_to_launch_maximized() {
        let mut value =
            serde_json::to_value(AppSettings::default()).expect("serialize default settings");
        let obj = value
            .as_object_mut()
            .expect("AppSettings serializes to a JSON object");
        // Simulate an on-disk config from the intermediate build: the canonical
        // key is absent and the former key is present (set to true so the
        // assertion proves the value carries over, not just that it parses).
        obj.remove("launch_maximized");
        obj.insert("launch_fullscreen".to_string(), serde_json::json!(true));

        let parsed: AppSettings = serde_json::from_value(value)
            .expect("config using the legacy launch_fullscreen key must still deserialize");
        assert!(
            parsed.launch_maximized,
            "the legacy launch_fullscreen value should carry over to launch_maximized"
        );
    }

    /// Configs predating the setting entirely (neither key present) must also
    /// load, defaulting the preference to off.
    #[test]
    fn missing_launch_key_defaults_to_off() {
        let mut value =
            serde_json::to_value(AppSettings::default()).expect("serialize default settings");
        value
            .as_object_mut()
            .expect("AppSettings serializes to a JSON object")
            .remove("launch_maximized");

        let parsed: AppSettings =
            serde_json::from_value(value).expect("config without the launch key must deserialize");
        assert!(
            !parsed.launch_maximized,
            "launch_maximized should default to false when absent"
        );
    }

    /// `auto_connect_server` used to default to `true` in `impl Default`
    /// while `#[serde(default)]` (used when an existing settings.json
    /// predates the field) fell back to `bool::default() == false` — a
    /// fresh install and an upgrade disagreed on whether a server connects
    /// automatically on startup. Both paths must agree, and connecting to a
    /// network automatically is significant enough behavior that "off"
    /// is the only safe shared default (see `auto_connect_kad`, which this
    /// mirrors).
    #[test]
    fn auto_connect_server_defaults_to_off_via_both_paths() {
        assert!(
            !AppSettings::default().auto_connect_server,
            "impl Default for AppSettings must default auto_connect_server to false"
        );

        let mut value =
            serde_json::to_value(AppSettings::default()).expect("serialize default settings");
        value
            .as_object_mut()
            .expect("AppSettings serializes to a JSON object")
            .remove("auto_connect_server");
        let parsed: AppSettings = serde_json::from_value(value)
            .expect("config without the auto_connect_server key must deserialize");
        assert!(
            !parsed.auto_connect_server,
            "auto_connect_server should default to false when absent from a saved config"
        );
    }
}
