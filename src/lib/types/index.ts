export interface FileInfo {
  id: string;
  name: string;
  path: string;
  size: number;
  hash: string;
  aich_hash: string;
  ember_file_hash: string;
  extension: string;
  modified_at: number;
  priority: 'verylow' | 'low' | 'normal' | 'high' | 'release' | 'auto';
  requests: number;
  accepted: number;
  bytes_transferred: number;
  alltime_requests: number;
  alltime_accepted: number;
  alltime_transferred: number;
  complete_sources: number;
  folder: string;
  shared: boolean;
  /**
   * Restricts an otherwise-shared file to mutual friends. Such a file is never
   * offered to a server, published to KAD, or served to a non-friend, so both
   * network badges stay dark while it is set.
   */
  friends_only: boolean;
  shared_kad: boolean;
  shared_ed2k: boolean;
  /**
   * A source record for this file is live on the Ember DHT. Set only once
   * storing peers have acknowledged the publish, so it means other Ember
   * users can find the file rather than that a publish was attempted.
   */
  shared_ember: boolean;
}

export interface PeerInfo {
  id: string;
  addresses: string[];
  nickname: string;
  last_seen: number;
  files_shared: number;
  banned: boolean;
}

export interface KadContact {
  id: string;
  type: number;
  version: number;
  distance: string;
  ip_verified: boolean;
  bootstrap: boolean;
}

export interface KadSearchEntry {
  /** K33: the backend id is a Rust u64. In theory it could exceed JS
   *  `Number.MAX_SAFE_INTEGER` (2^53 - 1), but the counter starts at 1 and
   *  increments by 1 per search, so we'd need billions of searches/sec for
   *  ~285 years to hit that. We keep the JSON-native `number` type here but
   *  the cancel command takes a string so there's always a safe escape hatch.
   */
  id: number;
  target: string;
  type: string;
  name: string;
  status: 'active' | 'stopping';
  load: number;
  load_response: number;
  load_total: number;
  packets_sent: number;
  request_answer: number;
  responses: number;
  /** K30: unix seconds; UI derives "age" column from this. */
  started_at: number;
}

export interface Transfer {
  id: string;
  file_name: string;
  file_hash: string;
  peer_id: string;
  peer_name: string;
  direction: 'upload' | 'download';
  status: 'searching' | 'queued' | 'active' | 'paused' | 'stopped' | 'verifying' | 'completing' | 'completed' | 'failed' | 'hashing' | 'insufficient' | 'noneneeded';
  progress: number;
  speed: number;
  total_size: number;
  transferred: number;
  /** Unique completed size. Downloads include resumed data; uploads are
   *  unique per-part coverage this session (re-requests do not inflate it). */
  completed_size: number;
  started_at: number;
  failure_reason?: string;
  failure_kind?: 'transient' | 'permanent' | 'download_timeout';
  failure_stage?: string;
  priority: 'verylow' | 'low' | 'normal' | 'high' | 'release' | 'auto';
  sources: number;
  active_sources: number;
  queued_sources: number;
  queue_rank?: number;
  last_seen_complete?: number;
  last_received?: number;
  health: 'healthy' | 'degraded' | 'stalled';
  health_reason?: string;
  stalled_since?: number;
  category: string;
  wait_time: number;
  upload_time: number;
  a4af_sources: number;
  max_sources: number;
  preview_priority: boolean;
  /** True when a live preview would currently succeed (first part verified +
   *  previewable media type). Drives the Preview action's enabled state. */
  preview_ready: boolean;
  ember_sources: number;
  client_software?: string;
  country_code?: string;
  user_hash?: string;
  /** Ember identity of an uploading peer. Friends are keyed by this, not `user_hash`. */
  ember_hash?: string;
  expected_aich?: string;
  /** Optional Ember content BLAKE3 (64 hex) from `eh=` / browse / offer. */
  ember_file_hash?: string;
  /** Downloads only: absolute path of the finished file on disk. Completion
   *  moves the `.part` to `Downloads/<name>`, but the backend deduplicates
   *  against an existing file by appending ` (n)` to the stem — so rebuilding
   *  the path from `file_name` points at the wrong file after a collision.
   *  Omitted from IPC until the download completes. */
  completed_path?: string;
  /** Upload-direction only: hex bitmap of ED2K parts fully served to this
   *  peer during the current session (byte index = part / 8, bit = part % 8,
   *  LSB-first within each byte). Drives the chunked "Up Status" parts bar —
   *  the analog of eMule's green `m_DoneBlocks_list` fill. */
  up_part_status?: string;
  /** Upload-direction only: total ED2K part count (ceil(total_size / PARTSIZE)),
   *  paired with {@link up_part_status} so the bar renders the right segments. */
  up_part_count?: number;
  /** Upload-direction only: hex bitmap (same packing as {@link up_part_status},
   *  shares {@link up_part_count}) of parts the downloader advertised it already
   *  had at request time — eMule's `m_abyUpPartStatus`. Shaded dark beneath the
   *  green served-this-session fill. */
  up_peer_part_status?: string;
  /** Downloads only: true once this completion re-checked the file's Ember
   *  content BLAKE3 hash on disk and it matched. Only ever set by a
   *  completion that actually ran the check — never inferred from
   *  `expected_aich`-style presence, since the crash-recovery re-verify
   *  path skips it. */
  ember_verified: boolean;
}

export interface SourceInfo {
  ip: string;
  port: number;
  status: 'connecting' | 'wait_callback' | 'friend_connect' | 'unreachable' | 'queued' | 'stalled' | 'queue_full' | 'no_needed_parts' | 'transferring' | 'completed' | 'failed';
  queue_rank?: number;
  speed: number;
  transferred: number;
  client_software: string;
  peer_name: string;
  available_parts?: number;
  total_parts?: number;
  country_code?: string;
  /** Stable peer identity (eD2k user hash). The backend field is a
   *  `[u8; 16]`, which serde emits as a 16-element byte array — not the hex
   *  string `Transfer.user_hash` carries. Absent while the identity is still
   *  unknown. Used backend-side to coalesce the same peer appearing at both
   *  its advertised listening port and the ephemeral port of an adopted
   *  inbound connection. */
  user_hash?: number[];
}

/** Media metadata for a search hit (eMule `FT_MEDIA_*` tags). */
export interface MediaMetadata {
  /** Playback length in whole seconds. */
  duration?: number;
  /** Bitrate in kbps. */
  bitrate?: number;
  codec?: string;
  artist?: string;
  album?: string;
  title?: string;
}

export interface SearchResult {
  file: FileInfo;
  peer_id: string;
  peer_name: string;
  availability: number;
  file_type: string;
  source_addresses: string[];
  rating?: number;
  comment?: string;
  media?: MediaMetadata;
  spam_rating: number;
  is_spam: boolean;
  clean_name: string;
  /** KAD, Server, UDP, Local, Notes, or combined labels from the backend */
  result_origin?: string;
}

export interface StartDownloadResponse {
  transfer_id: string;
  already_queued: boolean;
}

export interface SpamStats {
  spam_hashes: number;
  not_spam_hashes: number;
  spam_filenames: number;
  spam_server_ips: number;
  spam_source_ips: number;
}

export interface DownloadHistoryStats {
  completed: number;
  cancelled: number;
  total: number;
}

export interface SpamExplanation {
  score: number;
  threshold: number;
  profile: 'relaxed' | 'balanced' | 'aggressive';
  is_spam: boolean;
  reasons: string[];
}

export type SpamFilterProfile = 'relaxed' | 'balanced' | 'aggressive';

export interface NetworkStats {
  connected_peers: number;
  upload_speed: number;
  download_speed: number;
  total_uploaded: number;
  total_downloaded: number;
  status: 'connected' | 'connecting' | 'disconnected';
  external_ip: string;
  firewalled: boolean;
  buddy_status: 'none' | 'searching' | 'connecting' | 'connecting_lowid' | 'connected' | 'connected_lowid' | 'serving' | 'serving_lowid';
  upnp_mapped: boolean;
  stores_acknowledged: number;
  kad_users_estimate: number;
  tcp_status?: string;
  udp_status?: string;
  /** STUN-probed NAT class. `'Symmetric'` means friend hole-punching cannot
   *  work, so a firewalled peer needs port forwarding to transfer with a
   *  firewalled friend. `'Unknown'` before the probe resolves. */
  nat_type?: string;
  ember_peers: number;
  epx_sources_received: number;
  server_status?: string;
  stun_keepalive_active?: boolean;
  public_udp_port?: number;
  public_tcp_port?: number;
  tcp_mapping_hold_ok?: boolean;
  /** Ember-native Noise DHT enabled — drives the status-bar EmberDHT dot. */
  ember_native_enabled: boolean;
  /** Live Ember DHT routing-table contacts for the status-bar peer count. */
  ember_dht_contacts: number;
  /** Contacts that have answered us. Used for connected vs still-joining. */
  ember_dht_verified_contacts?: number;
  stale?: boolean;
  degraded?: boolean;
  /** Stable reason code (localized at render time via
   *  `degradedReasonText` in `$lib/i18n`), not a display string. */
  degraded_reason?: DegradedReason;
  last_update_at?: number;
  last_poll_ok_at?: number;
}

/** Why the network is considered degraded. Kept as a stable code so the
 *  UI can localize it; the store must never put a display string here. */
export type DegradedReason = 'stale' | 'limited' | 'establishing';

/** Diagnostic counters for the Ember mesh (EPX events, LowID broker
 *  outcomes, native transport ping/pong). Populated by
 *  `invoke('get_ember_diagnostics')`; surfaced separately from
 *  `NetworkStats` to keep the hot status-bar payload focused on
 *  user-visible state. */
export interface EmberDiagnostics {
  epx_events_received: number;
  ember_peers_known: number;
  broker_relay_attempts: number;
  broker_relay_successes: number;
  broker_relay_failures: number;
  broker_active_attempts: number;
  broker_relay_candidates: number;
  broker_oldest_attempt_age_secs: number;
  /** Friend transfers: requests asking a friend to dial us. */
  friend_xfer_connect_back_requested?: number;
  /** Friend transfers: requests asking for a coordinated hole-punch. */
  friend_xfer_punch_requested?: number;
  friend_xfer_accepted?: number;
  friend_xfer_declined?: number;
  /** Connections adopted into a waiting download — proves an end-to-end success. */
  friend_xfer_connected?: number;
  friend_xfer_timed_out?: number;
  friend_xfer_inbound_accepted?: number;
  friend_xfer_inbound_declined?: number;
  relay_sessions_active: number;
  relay_bytes_relayed: number;
  ember_native_enabled: boolean;
  ember_sessions: number;
  ember_pings_sent: number;
  ember_pings_received: number;
  ember_pongs_received: number;
  ember_exchange_requests_received: number;
  ember_exchange_sent: number;
  ember_exchange_received: number;
  local_noise_public_key: string;
  /** Our 128-bit Ember DHT node ID (hex), equal to the ember_hash. */
  ember_dht_node_id: string;
  /** Our Ed25519 public key (hex) — peers need it to add us as a contact. */
  local_ed25519_public_key: string;
  /** Live contacts in the Ember DHT routing table. */
  ember_dht_contacts: number;
  /** Of `ember_dht_contacts`, those that have actually answered us. The rest
   *  are gossip we have been told about and not yet reached, so a table that
   *  looks full while this stays near zero is a node that is not really in the
   *  network — which the total on its own cannot show. */
  ember_dht_verified_contacts: number;
  /** Rough size of the whole Ember network, from how tightly the peers we have
   *  proven are packed around our own ID. Zero while too few have answered for
   *  the density to mean anything. An estimate, and a determined peer could
   *  skew it, so treat it as a diagnostic rather than a fact. */
  ember_dht_estimated_nodes: number;
  /** Records held for other publishers that are due to be replicated onward
   *  and have not been yet. Persistently high means replication is falling
   *  behind its per-cycle budget. */
  ember_dht_republish_backlog: number;
  /** Seconds since any Ember DHT frame arrived, or 0 if none ever has. Separates
   *  "still joining" from "joined and quiet" from "stuck". */
  ember_dht_seconds_since_inbound: number;
  ember_dht_pings_sent: number;
  ember_dht_pings_received: number;
  ember_dht_pongs_received: number;
  ember_dht_find_nodes_sent: number;
  ember_dht_find_nodes_received: number;
  ember_dht_active_searches: number;
  ember_dht_stored_keys: number;
  ember_dht_stored_records: number;
  /** Of `ember_dht_stored_keys`, keys holding at least one record authored
   *  by someone other than us — see `ember_dht_stored_for_others_records`. */
  ember_dht_stored_for_others_keys: number;
  /** Of `ember_dht_stored_records`, how many were authored by someone other
   *  than us: what this node is genuinely storing on the network's behalf,
   *  rather than a record of its own that happens to be in its own store. */
  ember_dht_stored_for_others_records: number;
  ember_dht_stores_received: number;
  ember_dht_find_values_received: number;
  ember_dht_active_publishes: number;
  /** Maintenance loop (slice 6) counters. */
  ember_dht_refreshes: number;
  ember_dht_liveness_pings_sent: number;
  ember_dht_contacts_evicted: number;
  ember_dht_records_republished: number;
  /** KAD-bridge bootstrap pings sent this session (slice 13): while the DHT
   *  is still sparse, KAD-learned Ember peers are DHT-pinged so their signed
   *  PONG folds them into the routing table. Self-disables once bootstrapped. */
  ember_dht_kad_bridge_pings: number;
  /** Source records (re)published for our shared files this session (slice 9). */
  ember_dht_sources_published: number;
  /** Source lookups started for active/pending downloads this session (slice 9). */
  ember_dht_source_searches: number;
  /** Verified source records discovered via FIND_VALUE for downloads (slice 9). */
  ember_dht_source_records_found: number;
  /** Keyword records (re)published for our shared files this session (slice 8). */
  ember_dht_keywords_published: number;
  /** Slice 14: inbound Ember DHT frames dropped by per-IP rate limits. */
  ember_dht_rate_limited: number;
  /** Slice 14: STORE frames rejected as short-window signature replays. */
  ember_dht_store_replays: number;
  /** Slice 15: LowID/firewalled but still publishing Ember DHT sources. */
  ember_dht_firewalled_publishing: boolean;
  /** Slice 15: Ember on but no external IPv4 available for source records. */
  ember_dht_udp_unreachable: boolean;
  /** PROXY_STORE requests sent (firewalled publisher → HighID buddies). */
  ember_dht_buddy_publishes: number;
  /** PROXY_STORE requests accepted and fanned out as a buddy. */
  ember_dht_buddy_forwards: number;
  /** Outbound FIND_VALUE frames sent this session. */
  ember_dht_find_values_sent: number;
  /** Completed FIND_VALUE searches that gathered ≥1 record. */
  ember_dht_search_hits: number;
  /** Completed FIND_VALUE searches that returned no records. */
  ember_dht_search_misses: number;
  /** Iterative search rounds that dispatched ≥1 query. */
  ember_dht_search_rounds: number;
  /** Inbound FIND_VALUE answered with FOUND_VALUE. */
  ember_dht_find_value_hits: number;
  /** Inbound FIND_VALUE answered with FOUND_NODE. */
  ember_dht_find_value_misses: number;
  /**
   * Inbound FIND_VALUE answers that could not carry every matching record this
   * node holds. One datagram fits about five, and always the same five, so a
   * publisher behind them is never served from here.
   */
  ember_dht_found_value_truncated?: number;
  /** Records left out of those answers. */
  ember_dht_found_value_withheld?: number;
  /** Outbound STORE_ACK receipts this session. */
  ember_dht_stores_acked: number;
  /** Outbound STORE targets that failed/timed out. */
  ember_dht_stores_failed: number;
  /** Sum of acked counts across finished publishes. */
  ember_dht_replication_sum: number;
  /** Finished publish operations this session. */
  ember_dht_publishes_completed: number;
  /** Average STORE replication depth (acks per finished publish). */
  ember_dht_avg_replication: number;
  /** Slice 19: inbound frames rejected as malformed. */
  ember_dht_malformed: number;
  /** Frames refused at the version byte rather than misparsed. */
  ember_dht_version_mismatch?: number;
  /** Completed lookups of the Ember rendezvous key this session. */
  ember_dht_rendezvous_lookups?: number;
  /** Those lookups that returned no other Ember node after dropping self. */
  ember_dht_rendezvous_empty?: number;
  /** Advertised Ember nodes in the most recent rendezvous lookup (after dropping self). */
  ember_dht_rendezvous_last_peers?: number;
  /** Slice 19: observed-IP votes recorded from PONG payloads. */
  ember_dht_observed_votes: number;
  /** Slice 19: confirmed observed external address (`ip:port`), if any. */
  ember_dht_observed_addr?: string;
  /**
   * Shared files with a confirmed Ember DHT source record right now. Falls
   * again when a file is unshared or the overlay is switched off, unlike the
   * session counters above, and is the same set that lights the Library's
   * Ember badge.
   */
  ember_dht_published_files: number;
  /**
   * Every source listed in an EPX payload we accepted, before filtering. The
   * denominator for EPX yield — compare against `epx_sources_received` on
   * `NetworkStats`, which counts only those that reached a live download.
   */
  epx_sources_offered?: number;
  /**
   * EPX sources for a file we are downloading that were still dropped as
   * IP-filtered, banned, known-dead, or an unreachable LowID peer. A peer
   * feeding us junk shows up here.
   */
  epx_sources_filtered?: number;
  /**
   * UDP EPX replies dropped before sending because the payload could not fit
   * one Ember datagram. Otherwise indistinguishable from nobody asking.
   */
  epx_udp_oversized_skipped?: number;
  /**
   * Inbound DHT records refused because the store already holds its maximum
   * number of distinct keys. This cap has no eviction path.
   */
  ember_dht_store_key_cap_rejections?: number;
  /** STORE frames whose publisher signature did not parse, or whose DHT key did not match. */
  ember_dht_store_reject_verify?: number;
  /** STORE frames refused because the Ed25519 signature did not verify. */
  ember_dht_store_reject_signature?: number;
  /** STORE frames refused because the signed creation time was implausible. */
  ember_dht_store_reject_timestamp?: number;
  /** Source records refused by the per-IP cap. */
  ember_dht_store_reject_source_ip_cap?: number;
  /** Records refused because one publisher already holds its share of the key. */
  ember_dht_store_reject_publisher_cap?: number;
  /** Records refused because the key already holds its maximum. */
  ember_dht_store_reject_per_key_cap?: number;
  /** Source records whose declared IP did not match the Noise sender. */
  ember_dht_store_reject_source_ip?: number;
  /** STORE records for keys this node is not close enough to hold. */
  ember_dht_store_reject_proximity?: number;
  /** Completed FIND_VALUE searches this session (hits, misses, and timeouts). */
  ember_dht_search_outcomes?: number;
  /** Sum of shortlist nodes that answered across those searches. */
  ember_dht_search_nodes_answered?: number;
  /** Sum of FIND_VALUE durations in milliseconds. */
  ember_dht_search_elapsed_ms_sum?: number;
  /** Sum of verified records gathered across those searches. */
  ember_dht_search_records_sum?: number;
  /** Highest verified-contact count seen today (UTC). */
  ember_dht_verified_highwater_today?: number;
  /** Highest verified-contact count ever recorded on this node. */
  ember_dht_verified_highwater?: number;
}

/** Result of an `ember_ping_peer` harness round-trip. `rtt_ms` is set
 *  iff `success` is true. The `peerPubkeyHex` argument is optional —
 *  when omitted, the backend resolves the peer's Noise pubkey from
 *  the KAD-fed cache. */
export interface EmberPingResult {
  success: boolean;
  rtt_ms?: number;
  error?: string;
}

/** One Ember DHT routing-table contact, as returned by
 *  `get_ember_dht_contacts`. All key/id fields are hex-encoded.
 *  The UI snapshot omits `addr` so peer IPs never reach the webview. */
export interface EmberDhtContact {
  node_id: string;
  /** Present on harness `FIND_NODE` replies; omitted from the UI snapshot. */
  addr?: string;
  /** Present on harness replies; omitted from the UI snapshot. */
  noise_pub?: string;
  /** Present on harness replies; omitted from the UI snapshot. */
  ed25519_pub?: string;
  last_seen?: number;
  failed_queries?: number;
  /** XOR distance from our node ID, hex (slice 16). */
  distance?: string;
}

/** One in-flight Ember DHT iterative search (slice 16). */
export interface EmberDhtSearchEntry {
  id: number;
  type: string;
  target: string;
  keyword_count: number;
  results: number;
  queried: number;
  in_flight: number;
  responded: number;
  pending: number;
  complete: boolean;
  age_secs: number;
}

/** One live key in the local Ember DHT store (slice 16). */
export interface EmberDhtStoreEntry {
  key: string;
  record_count: number;
  keyword_records: number;
  source_records: number;
}

/** Result of a single-hop `ember_dht_find_node`: the contacts a peer
 *  answered with for a target ID, or the reason the lookup failed. */
export interface EmberDhtFindResult {
  success: boolean;
  contacts: EmberDhtContact[];
  rtt_ms?: number;
  error?: string;
}

/** Result of `ember_dht_publish_keyword`: the DHT key the signed record
 *  landed under and how many nodes acknowledged storing it. */
export interface EmberDhtPublishResult {
  success: boolean;
  key: string;
  stored_on: number;
  targets: number;
  error?: string;
}

/** One signed record returned by `ember_dht_find_value`. Only records
 *  whose publisher signature verified are surfaced. */
export interface EmberDhtRecordInfo {
  record_type: number;
  file_name: string;
  file_size: number;
  file_hash: string;
  publisher: string;
  timestamp: number;
}

/** Result of an iterative `ember_dht_find_value`: the verified records
 *  discovered for a keyword, or the reason the lookup failed. */
export interface EmberDhtFindValueResult {
  success: boolean;
  records: EmberDhtRecordInfo[];
  rtt_ms?: number;
  error?: string;
}

/** Result of `ember_dht_run_maintenance` (slice 6): how much work the
 *  forced maintenance cycle kicked off. */
export interface EmberDhtMaintenanceResult {
  success: boolean;
  buckets_refreshed: number;
  liveness_pings_sent: number;
  records_republished: number;
  announces_sent: number;
  kad_bridge_pings_sent: number;
  error?: string;
}

export interface ServerInfo {
  ip: string;
  port: number;
  name: string;
  description: string;
  user_count: number;
  file_count: number;
  max_users: number;
  soft_files: number;
  hard_files: number;
  is_static: boolean;
  fail_count: number;
  client_id: number;
  is_low_id: boolean;
}

/** Row in the upload-pane "Queued" tab. Mirrors `crate::types::UploadQueueClient`
 *  in the Rust backend; populated by `invoke('get_upload_queue')`. */
export interface UploadQueueClient {
  user_hash: string;
  peer_ip: string;
  peer_port: number;
  file_hash: string;
  file_name: string;
  wait_seconds: number;
  queue_rank: number | null;
  credit_ratio: number;
  uploaded: number;
  downloaded: number;
  ident_state: string;
  country_code: string | null;
  is_friend: boolean;
  emule_version: number;
}

/** Row in the upload-pane "Known ED2K Peers" / "Known Ember Peers"
 *  tabs. Mirrors `crate::types::KnownClient`. Populated by
 *  `invoke('get_known_clients')`. Ember-bound rows (`ember_hash` set)
 *  are shown only on the Ember tab. */
export interface KnownClient {
  user_hash: string;
  downloaded: number;
  uploaded: number;
  credit_ratio: number;
  last_seen: number;
  ident_state: string;
  last_known_ip: string | null;
  country_code: string | null;
  has_public_key: boolean;
  /** Ember node id hex when known; friends are keyed by this, not user_hash. */
  ember_hash: string | null;
  is_friend: boolean;
  /** Friend nickname from the friends DB when this row is a friend. */
  nickname?: string;
}

/** Snapshot of the anti-leech client filter — the eMule-style
 *  AntiLeech.dat equivalent. Populated by `invoke('get_antileech_patterns')`. */
export interface AntiLeechSnapshot {
  enabled: boolean;
  patterns: string[];
  file_path: string;
  pattern_count: number;
}

/** Result of `invoke('set_antileech_patterns')`. The backend accepts as
 *  many patterns as it can — patterns that fail to compile are surfaced
 *  per-row in `compile_errors` instead of failing the whole replacement. */
export interface AntiLeechReplaceResult {
  snapshot: AntiLeechSnapshot;
  compile_errors: Array<[string, string]>;
}

export interface AppSettings {
  nickname: string;
  /** Backend-owned: listed in `BACKEND_OWNED_SETTINGS_FIELDS`
   *  (`src-tauri/src/commands/settings.rs`), so `update_settings` restores it
   *  from the authoritative in-memory config and any value written here is
   *  discarded. Change shared folders through the sharing commands. */
  readonly shared_folders: string[];
  download_folder: string;
  max_upload_speed: number;
  max_download_speed: number;
  max_concurrent_downloads: number;
  max_concurrent_uploads: number;
  tcp_port: number;
  udp_port: number;
  nodes_dat_path: string;
  upnp_enabled: boolean;
  /** Keep full-cone/CGNAT mappings alive via STUN + TCP hold; advertise public ports. */
  stun_keepalive_enabled: boolean;
  obfuscation_enabled: boolean;
  ip_filter_enabled: boolean;
  filter_incoming_connections: boolean;
  /** Answer standard ed2k "View Files" requests from any compatible client
   *  (eMule, aMule, MLDonkey, ...) with our real shared-file list. Off by
   *  default. Unrelated to `friend_browse_disabled`, which gates the
   *  separate Ember-only friend browse feature. */
  allow_shared_files_browse: boolean;
  block_private_ips: boolean;
  filter_servers_by_ip: boolean;
  add_servers_from_server: boolean;
  add_servers_from_clients: boolean;
  server_list_path: string;
  auto_connect_kad: boolean;
  auto_connect_server: boolean;
  max_sources_per_file: number;
  max_connections: number;
  add_downloads_paused: boolean;
  remove_finished_downloads: boolean;
  /** Globally prioritize first/last part of every download for faster preview. */
  preview_priority_all: boolean;
  skip_compress_video: boolean;
  /** When on, peers whose advertised client-software string matches any
   *  pattern in `<data_dir>/antileech.dat` are rejected at handshake
   *  (software label plus mod tag). */
  antileech_enabled: boolean;
  uss_enabled: boolean;
  filename_cleanups: string;
  spam_filter_enabled: boolean;
  spam_filter_profile: SpamFilterProfile;
  /** Seconds to wait in remote upload queue before giving up (60–14400) */
  download_queue_wait_secs: number;
  /** Extra multi-source retry rounds after initial tasks (1–20) */
  multisource_retry_rounds: number;
  /** Per-source part hash failure retries during transfer (1–20) */
  download_part_retry_rounds: number;
  /** Max download size in GiB (1–593; default 593, the ed2k part-count ceiling) */
  max_download_file_size_gib: number;
  /** Global search / find-sources / find-notes timeout in seconds (30–600) */
  search_timeout_secs: number;
  /** When false, recent search queries are no longer persisted to local
   *  storage (the search-history dropdown), and any existing history is
   *  cleared. Defaults to true. */
  save_search_history: boolean;
  setup_complete: boolean;
  /** Internal migration marker; preserve when round-tripping settings.
   *  Backend-owned via `BACKEND_OWNED_SETTINGS_FIELDS`
   *  (`src-tauri/src/commands/settings.rs`) — a renderer write is discarded. */
  readonly default_shared_folder_seeded: boolean;
  /** Monotonic optimistic-concurrency token for settings saves. */
  settings_revision: number;
  /** Require approval before granting friend-slot priority */
  friend_require_approval: boolean;
  /** Disable incoming chat messages from friends */
  friend_chat_disabled: boolean;
  /** Disable browse-shares responses to friends */
  friend_browse_disabled: boolean;
  /** Encrypt friend sessions with RC4 obfuscation */
  friend_session_encryption: boolean;
  /** Maximum number of friends allowed (1–500) */
  max_friends: number;
  /** Rendezvous server URL for Ember friend discovery */
  rendezvous_url: string;
  /** Join the Ember-native Noise-encrypted overlay (UDP transport + DHT).
   *  Always on: the DHT bootstraps from other clients rather than a
   *  central pool, so it only works when ordinary profiles take part.
   *  The Settings / Ember-page switches are shown but cannot turn this off —
   *  which is enforced by `BACKEND_OWNED_SETTINGS_FIELDS`
   *  (`src-tauri/src/commands/settings.rs`) restoring it on every save. */
  readonly ember_native_enabled: boolean;
  /** Whether this node carries relay traffic for other peers. Relaying is what
   *  lets two firewalled peers reach each other, so it defaults on, but it
   *  spends this node's uplink on strangers and is therefore a choice. */
  relay_for_peers: boolean;
  /** Ceiling on concurrent relay sessions carried for others. `0` means use
   *  the built-in default rather than "relay nothing" — that is
   *  `relay_for_peers`. */
  max_relay_sessions: number;
  /** What to do when the user closes the main window via the title-bar X.
   *
   *  - `'ask'` (default): show a dialog letting the user pick.
   *  - `'tray'`: hide the window to the system tray; Ember keeps running.
   *  - `'exit'`: fully quit the application.
   */
  close_to_tray_behavior: 'ask' | 'tray' | 'exit';
  /** Maximize the main window on launch. Applied once at startup (the
   *  window is created at its configured size), so a change only affects
   *  the next launch. Off by default. */
  launch_maximized: boolean;
  /** Automatically check for updates shortly after launch, subject to
   *  `update_check_frequency`. The "Check for updates" button in Settings →
   *  About always works manually regardless of this setting. Defaults to
   *  true (Ember's original always-check-on-launch behavior). */
  auto_check_updates: boolean;
  /** How often the automatic background update check may run. */
  update_check_frequency: 'daily' | 'weekly' | 'monthly';
}
