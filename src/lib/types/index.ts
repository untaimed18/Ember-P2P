export interface FileInfo {
  id: string;
  name: string;
  path: string;
  size: number;
  hash: string;
  aich_hash: string;
  extension: string;
  modified_at: number;
}

export interface PeerInfo {
  id: string;
  addresses: string[];
  nickname: string;
  last_seen: number;
  files_shared: number;
  banned: boolean;
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
}

export interface SearchResult {
  file: FileInfo;
  peer_id: string;
  peer_name: string;
  availability: number;
  file_type: string;
  source_addresses: string[];
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
  buddy_status: string;
  upnp_mapped: boolean;
  stores_acknowledged: number;
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
  nat_traversal_enabled: boolean;
  upnp_enabled: boolean;
  obfuscation_enabled: boolean;
  ip_filter_enabled: boolean;
  block_private_ips: boolean;
}
