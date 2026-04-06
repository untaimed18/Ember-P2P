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
  ember_sources: number;
  client_software?: string;
  country_code?: string;
}

export interface SourceInfo {
  ip: string;
  port: number;
  status: 'connecting' | 'queued' | 'queue_full' | 'no_needed_parts' | 'transferring' | 'completed' | 'failed';
  queue_rank?: number;
  speed: number;
  transferred: number;
  client_software: string;
  peer_name: string;
  available_parts?: number;
  total_parts?: number;
  country_code?: string;
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

export interface SpamExplanation {
  score: number;
  threshold: number;
  profile: 'balanced' | 'aggressive';
  is_spam: boolean;
  reasons: string[];
}

export type SpamFilterProfile = 'balanced' | 'aggressive';

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
  degraded_reason?: string;
  last_update_at?: number;
  last_poll_ok_at?: number;
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
  skip_compress_video: boolean;
  uss_enabled: boolean;
  filename_cleanups: string;
  spam_filter_enabled: boolean;
  spam_filter_profile: SpamFilterProfile;
  /** Seconds to wait in remote upload queue before giving up (60–7200) */
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
}
