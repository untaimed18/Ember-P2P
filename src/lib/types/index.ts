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
  complete_sources: number;
  folder: string;
  shared_kad: boolean;
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
  status: 'searching' | 'queued' | 'active' | 'paused' | 'completed' | 'failed';
  progress: number;
  speed: number;
  total_size: number;
  transferred: number;
  started_at: number;
  failure_reason?: string;
  priority: 'low' | 'normal' | 'high' | 'auto';
  sources: number;
  active_sources: number;
  queued_sources: number;
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
}

export interface NetworkStats {
  connected_peers: number;
  upload_speed: number;
  download_speed: number;
  total_uploaded: number;
  total_downloaded: number;
  status: 'connected' | 'connecting' | 'disconnected';
  external_ip: string;
  firewalled: boolean;
  /** Backend sends: 'none', 'connecting_...', 'connected_...', 'serving_...' */
  buddy_status: 'none' | 'connecting' | 'connected' | 'serving' | string;
  upnp_mapped: boolean;
  stores_acknowledged: number;
}

export interface ServerInfo {
  ip: string;
  port: number;
  name: string;
  description: string;
  user_count: number;
  file_count: number;
  is_static: boolean;
  fail_count: number;
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
  block_private_ips: boolean;
}
