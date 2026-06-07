export interface FileInfo {
  id: string;
  name: string;
  path: string;
  size: number;
  hash: string;
  aich_hash: string;
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
  shared_kad: boolean;
  shared_ed2k: boolean;
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
}

export interface SourceInfo {
  ip: string;
  port: number;
  status: 'connecting' | 'wait_callback' | 'queued' | 'stalled' | 'queue_full' | 'no_needed_parts' | 'transferring' | 'completed' | 'failed';
  queue_rank?: number;
  speed: number;
  transferred: number;
  client_software: string;
  peer_name: string;
  available_parts?: number;
  total_parts?: number;
  country_code?: string;
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
  buddy_status: 'none' | 'connecting' | 'connecting_lowid' | 'connected' | 'connected_lowid' | 'serving' | 'serving_lowid';
  upnp_mapped: boolean;
  stores_acknowledged: number;
  kad_users_estimate: number;
  tcp_status?: string;
  udp_status?: string;
  ember_peers: number;
  epx_sources_received: number;
  server_status?: string;
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
  broker_punch_attempts: number;
  broker_punch_successes: number;
  broker_punch_failures: number;
  broker_relay_attempts: number;
  broker_relay_successes: number;
  broker_relay_failures: number;
  ember_native_enabled: boolean;
  ember_sessions: number;
  ember_pings_sent: number;
  ember_pings_received: number;
  ember_pongs_received: number;
  local_noise_public_key: string;
  /** Our 128-bit Ember DHT node ID (hex), equal to the ember_hash. */
  ember_dht_node_id: string;
  /** Our Ed25519 public key (hex) — peers need it to add us as a contact. */
  local_ed25519_public_key: string;
  /** Live contacts in the Ember DHT routing table. */
  ember_dht_contacts: number;
  ember_dht_pings_sent: number;
  ember_dht_pings_received: number;
  ember_dht_pongs_received: number;
  ember_dht_find_nodes_sent: number;
  ember_dht_find_nodes_received: number;
  ember_dht_active_searches: number;
  ember_dht_stored_keys: number;
  ember_dht_stored_records: number;
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
 *  `get_ember_dht_contacts`. All key/id fields are hex-encoded. */
export interface EmberDhtContact {
  node_id: string;
  addr: string;
  noise_pub: string;
  ed25519_pub: string;
  last_seen: number;
  failed_queries: number;
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

/** Row in the upload-pane "Known Clients" tab. Mirrors
 *  `crate::types::KnownClient`. Populated by `invoke('get_known_clients')`. */
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
  shared_folders: string[];
  download_folder: string;
  max_upload_speed: number;
  max_download_speed: number;
  max_concurrent_downloads: number;
  max_concurrent_uploads: number;
  tcp_port: number;
  udp_port: number;
  nodes_dat_path: string;
  upnp_enabled: boolean;
  obfuscation_enabled: boolean;
  ip_filter_enabled: boolean;
  filter_incoming_connections: boolean;
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
   *  pattern in `<data_dir>/antileech.dat` are rejected at handshake. */
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
  /** Max download size in GiB (1–16384; default 4096 ≈ 4 TiB) */
  max_download_file_size_gib: number;
  /** Global search / find-sources / find-notes timeout in seconds (30–600) */
  search_timeout_secs: number;
  setup_complete: boolean;
  /** Require approval before granting friend-slot priority */
  friend_require_approval: boolean;
  /** Disable incoming chat messages from friends */
  friend_chat_disabled: boolean;
  /** Disable browse-shares responses to friends */
  friend_browse_disabled: boolean;
  /** Show notification when a friend comes online */
  friend_online_notifications: boolean;
  /** Encrypt friend sessions with RC4 obfuscation */
  friend_session_encryption: boolean;
  /** Maximum number of friends allowed (1–500) */
  max_friends: number;
  /** Rendezvous server URL for Ember friend discovery */
  rendezvous_url: string;
  /** Experimental: enable the Ember-native Noise-encrypted UDP transport. */
  ember_native_enabled: boolean;
  /** Advanced: reveal the Ember developer console (`/dev/ember`) links in the UI. */
  ember_dev_tools_enabled: boolean;
  /** What to do when the user closes the main window via the title-bar X.
   *
   *  - `'ask'` (default): show a dialog letting the user pick.
   *  - `'tray'`: hide the window to the system tray; Ember keeps running.
   *  - `'exit'`: fully quit the application.
   */
  close_to_tray_behavior: 'ask' | 'tray' | 'exit';
}
