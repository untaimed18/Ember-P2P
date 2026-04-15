use std::collections::HashMap;
use std::io::{Read, Seek, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use flate2::read::{DeflateDecoder, ZlibDecoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::sharing::manager::TransferControl;
use crate::types::Ed2kDownloadLimits;

use super::credits::{CreditManager, IdentState};
use super::comments::CommentManager;
use super::messages::*;
use super::part_tracker::PartTracker;
use super::sources::SourceManager;

const READ_TIMEOUT_SECS: u64 = super::dead_sources::DOWNLOADTIMEOUT_SECS as u64;

/// Maximum decompressed part size (PARTSIZE + margin = 10 MiB)
const MAX_DECOMPRESSED_PART: usize = 10 * 1024 * 1024;

/// Returns `true` if the IP should be rejected as a source exchange result
/// (unspecified, loopback, RFC-1918 private, or link-local).
pub(super) fn is_filtered_source_ip(ip: &std::net::Ipv4Addr) -> bool {
    ip.is_unspecified() || ip.is_loopback() || ip.is_private() || ip.is_link_local()
}

/// Convert parsed EPX result into the flattened vectors used by DownloadEvent.
pub(super) fn epx_result_to_entries(
    result: &crate::network::ember::ExchangeResult,
) -> (
    Vec<([u8; 16], Vec<(std::net::Ipv4Addr, u16, u16, u8)>)>,
    Vec<([u8; 16], [u8; 20])>,
) {
    let entries = result
        .files
        .iter()
        .map(|e| {
            let srcs = e.sources.iter().map(|s| (s.ip, s.tcp_port, s.udp_port, s.flags)).collect();
            (e.file_hash, srcs)
        })
        .collect();
    let aich_roots = result
        .files
        .iter()
        .filter_map(|e| e.aich_root.map(|r| (e.file_hash, r)))
        .collect();
    (entries, aich_roots)
}

#[derive(Debug)]
struct PendingCompressedBlock {
    #[allow(dead_code)]
    compressed_total_size: u32,
    compressed: Vec<u8>,
}

pub struct Ed2kDownload {
    pub transfer_id: String,
    pub file_hash: [u8; 16],
    pub file_name: String,
    pub file_size: u64,
    pub source_addr: SocketAddr,
    pub download_dir: PathBuf,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub bandwidth_limiter: Arc<BandwidthLimiter>,
    pub control: Arc<TransferControl>,
    pub source_manager: Option<Arc<tokio::sync::RwLock<SourceManager>>>,
    pub comment_manager: Option<Arc<tokio::sync::RwLock<CommentManager>>>,
    pub credit_manager: Option<Arc<tokio::sync::RwLock<CreditManager>>>,
    pub obfuscation_enabled: bool,
    pub ed2k_limits: Ed2kDownloadLimits,
    /// Our Ember identity hash, sent in EmuleInfo for friend identification
    pub ember_hash: [u8; 16],
    /// Our nickname for friend request messages
    pub our_nickname: String,
    /// Live friend user-hash set for detecting friend connections
    pub friend_hashes: Option<Arc<tokio::sync::RwLock<std::collections::HashSet<[u8; 16]>>>>,
    /// Pre-built Ember Peer Exchange payload (shared across tasks, read-only).
    pub ember_payload: crate::network::ember::SharedEmberPayload,
    /// Generation counter for detecting payload changes (for periodic re-sends).
    pub ember_payload_generation: crate::network::ember::EmberPayloadGeneration,
    /// IP filter for blocking known-bad ranges on SX receive
    pub ip_filter: Option<crate::network::kad::ip_filter::SharedIpFilter>,
    /// Banned peer IPs for rejecting SX sources
    pub banned_ips: Option<super::upload::SharedBannedIps>,
    /// Our external IP for self-source prevention
    pub external_ip: Option<std::net::Ipv4Addr>,
    /// Shared pending AICH recovery retries (read to gate OP_AICHREQUEST)
    pub aich_pending: Option<SharedAichPending>,
    /// GeoIP reader for country code lookups
    pub geoip: crate::geoip::GeoIpReader,
}

/// eMule-style error classification: only protocol-level failures (FNF, hash
/// mismatch) should mark a source dead.  Transient TCP errors like connection
/// resets or EOF are normal in P2P and the source should be reasked later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceFailureKind {
    /// Connection reset, EOF, timeout -- source should be reasked later
    Transient,
    /// File Not Found, hash mismatch -- source should be marked dead
    Permanent,
    /// Download timed out (100s no data) -- source goes back to OnQueue
    DownloadTimeout,
}

#[derive(Debug, Clone)]
pub enum DownloadEvent {
    Progress {
        transfer_id: String,
        downloaded: u64,
        total: u64,
    },
    SourcesUpdate {
        transfer_id: String,
        total: u32,
        active: u32,
        queued: u32,
    },
    Verifying {
        transfer_id: String,
    },
    SourceDetail {
        transfer_id: String,
        ip: String,
        port: u16,
        status: String,
        queue_rank: Option<u32>,
        speed: u64,
        transferred: u64,
        client_software: String,
        peer_name: String,
        failure_kind: Option<SourceFailureKind>,
        available_parts: Option<u32>,
        total_parts: Option<u32>,
        country_code: Option<String>,
    },
    Completed {
        transfer_id: String,
    },
    Failed {
        transfer_id: String,
        error: String,
        failure_kind: SourceFailureKind,
    },
    /// Sources discovered via source exchange from a connected peer.
    /// The network loop injects these into the active download.
    SourceExchange {
        transfer_id: String,
        file_hash: [u8; 16],
        sources: Vec<SourceExchangeEntry>,
    },
    /// Sources discovered via Ember Peer Exchange from another Ember client.
    EmberSources {
        transfer_id: String,
        entries: Vec<([u8; 16], Vec<(std::net::Ipv4Addr, u16, u16, u8)>)>,
        aich_roots: Vec<([u8; 16], [u8; 20])>,
        ember_peers: Vec<(std::net::Ipv4Addr, u16)>,
    },
    /// An Ember peer was detected (for peer discovery mesh bootstrap).
    EmberPeerDiscovered {
        ip: std::net::Ipv4Addr,
        tcp_port: u16,
    },
    /// Incoming friend request from an Ember peer.
    EmberFriendRequest {
        ember_hash: [u8; 16],
        nickname: String,
        peer_ip: String,
        peer_port: u16,
    },
    /// An Ember friend was seen on a download connection (EmuleInfo exchange completed).
    FriendSeen {
        ember_hash: [u8; 16],
        ip: std::net::IpAddr,
        port: u16,
    },
    /// Incoming Ember chat message from a friend on a download connection.
    EmberChatMessage {
        ember_hash: [u8; 16],
        message: String,
    },
    /// Incoming Ember browse response from a friend on a download connection.
    EmberBrowseResponse {
        ember_hash: [u8; 16],
        entries: Vec<(String, u64, String)>,
    },
    /// The .part file has been created on disk, signalling the network loop to
    /// offer this partial to the server and publish to KAD so other peers can
    /// discover us as a source.
    PartFileReady {
        transfer_id: String,
        file_hash: [u8; 16],
        file_size: u64,
        file_name: String,
    },
    /// A data block was received and written to disk — feeds the corruption blackbox.
    DataReceived {
        file_hash: [u8; 16],
        start: u64,
        end: u64,
        sender_ip: std::net::Ipv4Addr,
    },
    /// A part passed its MD4 hash check.
    PartVerified {
        file_hash: [u8; 16],
        part_start: u64,
        part_end: u64,
    },
    /// A part failed its MD4 hash check.
    PartCorrupted {
        file_hash: [u8; 16],
        part_start: u64,
        part_end: u64,
    },
    /// AICH recovery was attempted for a corrupt part but failed (timeout, bad data, etc.).
    /// The network loop uses this to schedule a retry with a different source.
    AichRecoveryFailed {
        file_hash: [u8; 16],
        part_index: u32,
        failed_ip: std::net::Ipv4Addr,
    },
}

/// Shared pending AICH recovery retries: `(file_hash, part_index) -> (failed_ips, retry_count)`.
/// Written by the network event loop, read by download tasks before sending OP_AICHREQUEST.
pub type SharedAichPending = std::sync::Arc<std::sync::RwLock<
    std::collections::HashMap<([u8; 16], u32), (Vec<std::net::Ipv4Addr>, u32)>,
>>;

#[derive(Debug, Clone)]
pub struct SourceExchangeEntry {
    pub ip: std::net::Ipv4Addr,
    pub tcp_port: u16,
    pub user_hash: [u8; 16],
    pub crypt_options: u8,
}

/// Classify an error string into transient vs permanent failure.
pub fn classify_error(err: &str) -> SourceFailureKind {
    let lower = err.to_lowercase();
    if lower.contains("does not have the file")
        || lower.contains("filereqansnofil")
        || lower.contains("file not found")
        || lower.contains("hash mismatch")
        || lower.contains("hash verification failed")
    {
        SourceFailureKind::Permanent
    } else if lower.contains("download timeout")
        || lower.contains("more than 100 seconds")
    {
        SourceFailureKind::DownloadTimeout
    } else {
        SourceFailureKind::Transient
    }
}

pub(crate) fn failure_kind_name(kind: &SourceFailureKind) -> String {
    match kind {
        SourceFailureKind::Transient => "transient".to_string(),
        SourceFailureKind::Permanent => "permanent".to_string(),
        SourceFailureKind::DownloadTimeout => "download_timeout".to_string(),
    }
}

pub(crate) fn summarize_error(error: &str, kind: &SourceFailureKind) -> String {
    let lower = error.to_lowercase();
    if lower.contains("cancelled") {
        return "Cancelled".to_string();
    }
    if lower.contains("does not have the file")
        || lower.contains("filereqansnofil")
        || lower.contains("file not found")
    {
        return "Remote missing file".to_string();
    }
    if lower.contains("hash mismatch") || lower.contains("hash verification failed") {
        return "Hash mismatch".to_string();
    }
    if matches!(kind, SourceFailureKind::DownloadTimeout) {
        return "Download timed out".to_string();
    }
    match infer_stage_from_error(error) {
        "tcp_connect" => "Connection failed".to_string(),
        "hello_wait" | "emule_info_wait" | "file_status_wait" => {
            "Peer handshake failed".to_string()
        }
        "queue_wait" => "Queue wait interrupted".to_string(),
        "hashset_wait" => "Hashset request failed".to_string(),
        "data_wait" => "Connection lost during transfer".to_string(),
        _ => match kind {
            SourceFailureKind::Permanent => "Permanent transfer failure".to_string(),
            SourceFailureKind::Transient => "Transient connection failure".to_string(),
            SourceFailureKind::DownloadTimeout => "Download timed out".to_string(),
        },
    }
}

pub(crate) fn infer_stage_from_error(error: &str) -> &'static str {
    if error.contains("stage:tcp_connect") {
        return "tcp_connect";
    }
    if error.contains("stage:hello_wait") {
        return "hello_wait";
    }
    if error.contains("stage:emule_info_wait") {
        return "emule_info_wait";
    }
    if error.contains("stage:file_status_wait") {
        return "file_status_wait";
    }
    if error.contains("stage:queue_wait") {
        return "queue_wait";
    }
    if error.contains("stage:queue_detached") {
        return "queue_wait";
    }
    if error.contains("stage:data_wait") {
        return "data_wait";
    }
    if error.contains("stage:hashset_wait") {
        return "hashset_wait";
    }
    if error.contains("HelloAnswer") {
        return "hello_wait";
    }
    if error.contains("upload slot") || error.contains("queue") {
        return "queue_wait";
    }
    if error.contains("hashset") {
        return "hashset_wait";
    }
    "unknown"
}

pub(crate) fn is_queue_detached_error(error: &str) -> bool {
    error.contains("stage:queue_detached") || error.contains("connection lost while queued")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ed2k::hash::{ed2k_hash_bytes, PARTSIZE};
    use md4::{Digest, Md4};

    #[test]
    fn verify_hashset_single_part_under_partsize() {
        let data: Vec<u8> = (0u8..100).collect();
        let file_hash_hex = ed2k_hash_bytes(&data);
        let mut file_hash = [0u8; 16];
        file_hash.copy_from_slice(&hex::decode(file_hash_hex).unwrap());
        let part_hash: [u8; 16] = Md4::digest(&data).into();
        assert!(verify_hashset(&file_hash, &[part_hash], data.len() as u64));
    }

    #[test]
    fn verify_hashset_exactly_partsize_one_hash() {
        // eMule: size == PARTSIZE needs hashset; file hash is MD4(MD4(data) ‖ MD4("")).
        let data = vec![0xABu8; PARTSIZE as usize];
        let file_hash_hex = ed2k_hash_bytes(&data);
        let mut file_hash = [0u8; 16];
        file_hash.copy_from_slice(&hex::decode(file_hash_hex).unwrap());
        let part_hash: [u8; 16] = Md4::digest(&data).into();
        assert!(
            verify_hashset(&file_hash, &[part_hash], PARTSIZE),
            "single-hash path must not treat PARTSIZE file as small-file MD4(data)"
        );
    }

    #[test]
    fn verify_hashset_two_parts_not_multiple() {
        let n = PARTSIZE as usize + 500;
        let data: Vec<u8> = (0..n).map(|i| (i % 256) as u8).collect();
        let file_hash_hex = ed2k_hash_bytes(&data);
        let mut file_hash = [0u8; 16];
        file_hash.copy_from_slice(&hex::decode(file_hash_hex).unwrap());
        let h1: [u8; 16] = Md4::digest(&data[..PARTSIZE as usize]).into();
        let h2: [u8; 16] = Md4::digest(&data[PARTSIZE as usize..]).into();
        assert!(verify_hashset(&file_hash, &[h1, h2], n as u64));
    }

    #[test]
    fn verify_hashset_two_full_parts_appends_sentinel() {
        let n = (2 * PARTSIZE) as usize;
        let data = vec![0xCDu8; n];
        let file_hash_hex = ed2k_hash_bytes(&data);
        let mut file_hash = [0u8; 16];
        file_hash.copy_from_slice(&hex::decode(file_hash_hex).unwrap());
        let h1: [u8; 16] = Md4::digest(&data[..PARTSIZE as usize]).into();
        let h2: [u8; 16] = Md4::digest(&data[PARTSIZE as usize..]).into();
        assert!(verify_hashset(&file_hash, &[h1, h2], n as u64));
    }

    #[test]
    fn summarize_timeout_error_is_user_friendly() {
        let kind = classify_error("stage:data_wait download timeout: no data for 100s");
        assert_eq!(kind, SourceFailureKind::DownloadTimeout);
        assert_eq!(summarize_error("stage:data_wait download timeout: no data for 100s", &kind), "Download timed out");
        assert_eq!(failure_kind_name(&kind), "download_timeout");
    }

    #[test]
    fn summarize_missing_file_error_is_user_friendly() {
        let kind = classify_error("peer does not have the file");
        assert_eq!(kind, SourceFailureKind::Permanent);
        assert_eq!(summarize_error("peer does not have the file", &kind), "Remote missing file");
    }
}

impl Ed2kDownload {
    /// Check if an SX-received source should be rejected (IP filter, banned,
    /// self-source). Returns true if the source should be skipped.
    fn is_sx_source_rejected(&self, ip: &std::net::Ipv4Addr, port: u16) -> bool {
        if let Some(ext_ip) = self.external_ip {
            if *ip == ext_ip && port == self.tcp_port {
                return true;
            }
        }
        if let Some(ref filter) = self.ip_filter {
            if let Ok(snap) = filter.read() {
                if snap.is_blocked(*ip) {
                    return true;
                }
            }
        }
        if let Some(ref banned) = self.banned_ips {
            if let Ok(set) = banned.read() {
                if set.contains(ip) {
                    return true;
                }
            }
        }
        false
    }

    async fn check_control(&self) -> anyhow::Result<()> {
        if self.control.is_cancelled() {
            anyhow::bail!("cancelled by user");
        }
        while self.control.is_paused() {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            if self.control.is_cancelled() {
                anyhow::bail!("cancelled while paused");
            }
        }
        Ok(())
    }

    /// Zero-byte ed2k files: no P2P; hash must be MD4 of empty payload ([`super::hash::empty_ed2k_file_md4`]).
    async fn complete_zero_byte_local(&self, event_tx: &mpsc::Sender<DownloadEvent>) -> anyhow::Result<()> {
        self.emit_source_detail(event_tx, "connecting", None, 0, 0, "", "").await;
        let _ = event_tx
            .send(DownloadEvent::Verifying {
                transfer_id: self.transfer_id.clone(),
            })
            .await;
        finalize_zero_ed2k_file(
            &self.transfer_id,
            &self.file_name,
            self.file_hash,
            &self.download_dir,
        )
        .await?;
        self.emit_source_detail(event_tx, "completed", None, 0, 0, "", "").await;
        let _ = event_tx
            .send(DownloadEvent::Progress {
                transfer_id: self.transfer_id.clone(),
                downloaded: 0,
                total: 0,
            })
            .await;
        Ok(())
    }

    async fn emit_source_detail(
        &self,
        event_tx: &mpsc::Sender<DownloadEvent>,
        status: &str,
        queue_rank: Option<u32>,
        speed: u64,
        transferred: u64,
        client_software: &str,
        peer_name: &str,
    ) {
        self.emit_source_detail_parts(event_tx, status, queue_rank, speed, transferred, client_software, peer_name, None, None).await;
    }

    fn country_code(&self) -> Option<String> {
        crate::geoip::lookup_country(&self.geoip, self.source_addr.ip())
    }

    async fn emit_source_detail_parts(
        &self,
        event_tx: &mpsc::Sender<DownloadEvent>,
        status: &str,
        queue_rank: Option<u32>,
        speed: u64,
        transferred: u64,
        client_software: &str,
        peer_name: &str,
        available_parts: Option<u32>,
        total_parts: Option<u32>,
    ) {
        let _ = event_tx
            .send(DownloadEvent::SourceDetail {
                transfer_id: self.transfer_id.clone(),
                ip: self.source_addr.ip().to_string(),
                port: self.source_addr.port(),
                status: status.to_string(),
                queue_rank,
                speed,
                transferred,
                client_software: client_software.to_string(),
                peer_name: peer_name.to_string(),
                failure_kind: None,
                available_parts,
                total_parts,
                country_code: self.country_code(),
            })
            .await;
    }

    async fn emit_source_failed(
        &self,
        event_tx: &mpsc::Sender<DownloadEvent>,
        error: &str,
        transferred: u64,
        client_software: &str,
        peer_name: &str,
    ) {
        let _ = event_tx
            .send(DownloadEvent::SourceDetail {
                transfer_id: self.transfer_id.clone(),
                ip: self.source_addr.ip().to_string(),
                port: self.source_addr.port(),
                status: "failed".to_string(),
                queue_rank: None,
                speed: 0,
                transferred,
                client_software: client_software.to_string(),
                peer_name: peer_name.to_string(),
                failure_kind: Some(classify_error(error)),
                available_parts: None,
                total_parts: None,
                country_code: self.country_code(),
            })
            .await;
    }

    /// Run a download on a pre-established connection (Hello handshake already done).
    /// Used for KAD callback connections where the firewalled source connected to us.
    pub async fn run_from_callback(
        self,
        mut reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        mut writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
        peer_user_hash: [u8; 16],
        emule_info_done: bool,
        event_tx: mpsc::Sender<DownloadEvent>,
    ) -> anyhow::Result<()> {
        info!(
            "Starting callback download {} from {}",
            hex::encode(self.file_hash), self.source_addr
        );

        if self.file_size == 0 {
            self.complete_zero_byte_local(&event_tx).await?;
            let _ = event_tx
                .send(DownloadEvent::Completed {
                    transfer_id: self.transfer_id.clone(),
                })
                .await;
            return Ok(());
        }

        self.emit_source_detail(&event_tx, "connected (callback)", None, 0, 0, "", "").await;

        if let Some(sm) = &self.source_manager {
            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                let mut sm = sm.write().await;
                sm.register_source(self.file_hash, v4, self.source_addr.port());
            }
        }

        match self.download_from_streams(
            &mut *reader,
            &mut *writer,
            peer_user_hash,
            PeerCapabilities::default(),
            &event_tx,
            emule_info_done,
        ).await {
            Ok(_) => {
                let _ = event_tx
                    .send(DownloadEvent::Completed {
                        transfer_id: self.transfer_id.clone(),
                    })
                    .await;
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                let kind = classify_error(&msg);
                let _ = event_tx
                    .send(DownloadEvent::Failed {
                        transfer_id: self.transfer_id.clone(),
                        error: msg,
                        failure_kind: kind,
                    })
                    .await;
                Ok(())
            }
        }
    }

    async fn download_from_streams(
        &self,
        mut reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
        mut writer: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
        peer_user_hash: [u8; 16],
        initial_caps: PeerCapabilities,
        event_tx: &mpsc::Sender<DownloadEvent>,
        skip_emule_info: bool,
    ) -> anyhow::Result<()> {
        let mut peer_supports_large_files = initial_caps.supports_large_files;
        let mut peer_supports_multipacket = initial_caps.supports_multi_packet;
        let mut peer_supports_ext_multipacket = initial_caps.ext_multi_packet;
        let mut peer_supports_file_ident = initial_caps.supports_file_ident;
        let mut peer_supports_source_ex2 = initial_caps.supports_source_ex2;
        let mut peer_supports_aich = initial_caps.supports_aich;
        let mut peer_source_exchange_ver: u8 = initial_caps.source_exchange_ver;
        let mut peer_extended_requests_ver: u8 = initial_caps.extended_requests_ver;
        let mut peer_secure_ident_level: u8 = initial_caps.secure_ident_level;
        let mut peer_is_ember = initial_caps.is_ember;
        let mut peer_ember_hash: Option<[u8; 16]> = initial_caps.ember_hash;
        let mut epx_packets_received: u8 = 0;
        let mut early_upload_accept = false;
        let mut pending_secident_challenge: Option<u32> = None;
        let mut pending_peer_challenge: Option<(u32, u8)> = None;

        let mut deferred_packet: Option<(u8, u8, Vec<u8>)> = None;
        let mut client_software_label = client_software_from_caps(&initial_caps);
        let mut peer_name_label = initial_caps.peer_name.clone();

        let peer_is_new_emule = initial_caps.emule_version_min > 0 || initial_caps.version_major > 0;
        if skip_emule_info || peer_is_new_emule {
            debug!("Skipping EmuleInfo exchange (already done via obfuscation or Hello eMule tags)");
        } else {
            let emule_payload = build_emule_info(self.udp_port, self.obfuscation_enabled, Some(&self.ember_hash));
            write_packet_async(&mut writer, OP_EMULEPROT, OP_EMULEINFO, &emule_payload).await?;

            let (proto2, opcode2, payload2) = read_packet_with_timeout(&mut reader)
                .await
                .context("stage:emule_info_wait")?;
            if proto2 == OP_EMULEPROT && opcode2 == OP_EMULEINFOANSWER {
                let mut peer_caps = initial_caps.clone();
                merge_caps(&mut peer_caps, parse_emule_info(&payload2));
                debug!(
                    "Peer caps: compress={}, large_files={}, sx={}/{}, kad={}/{}, \
                     crypt={}/{}/{}, multi={}/{}, aich={}, unicode={}, secident={}, \
                     preview={}, captcha={}, file_ident={}, direct_cb={}, \
                     compat={}, emule_min={}, mod={}",
                    peer_caps.compression_ver, peer_caps.supports_large_files,
                    peer_caps.source_exchange_ver, peer_caps.supports_source_ex2,
                    peer_caps.kad_version, peer_caps.kad_port,
                    peer_caps.supports_crypt_layer, peer_caps.requests_crypt_layer,
                    peer_caps.requires_crypt_layer,
                    peer_caps.supports_multi_packet, peer_caps.ext_multi_packet,
                    peer_caps.supports_aich, peer_caps.supports_unicode,
                    peer_caps.supports_secure_ident, peer_caps.supports_preview,
                    peer_caps.supports_captcha, peer_caps.supports_file_ident,
                    peer_caps.supports_direct_udp_callback,
                    peer_caps.compatible_client, peer_caps.emule_version_min,
                    peer_caps.mod_version,
                );
                let peer_udp = peer_caps.udp_port;
                peer_supports_large_files = peer_caps.supports_large_files;
                peer_supports_multipacket = peer_caps.supports_multi_packet;
                peer_supports_ext_multipacket = peer_caps.ext_multi_packet;
                peer_supports_file_ident = peer_caps.supports_file_ident;
                peer_supports_source_ex2 = peer_caps.supports_source_ex2;
                peer_source_exchange_ver = peer_caps.source_exchange_ver;
                peer_supports_aich = peer_caps.supports_aich;
                peer_extended_requests_ver = peer_caps.extended_requests_ver;
                peer_secure_ident_level = peer_caps.secure_ident_level;
                peer_is_ember = peer_caps.is_ember;
                peer_ember_hash = peer_caps.ember_hash;
                client_software_label = client_software_from_caps(&peer_caps);
                if !peer_caps.peer_name.is_empty() {
                    peer_name_label = peer_caps.peer_name.clone();
                }
                if peer_udp > 0 {
                    if let Some(sm) = &self.source_manager {
                        let mut sm = sm.write().await;
                        if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                            sm.register_source_full(self.file_hash, v4, self.source_addr.port(), peer_udp, peer_user_hash);
                        }
                    }
                    debug!("Got EmuleInfoAnswer (peer UDP port: {peer_udp})");
                } else {
                    debug!("Got EmuleInfoAnswer");
                }
                pending_secident_challenge = maybe_send_secident_challenge(
                    &mut writer,
                    self.credit_manager.as_ref(),
                    peer_user_hash,
                    self.source_addr,
                    peer_secure_ident_level,
                ).await?;
            } else if proto2 == OP_EMULEPROT && opcode2 == OP_EMULEINFO {
                // Peer sent OP_EMULEINFO instead of OP_EMULEINFOANSWER — parse
                // their capabilities and reply with our OP_EMULEINFOANSWER.
                let mut peer_caps = initial_caps.clone();
                merge_caps(&mut peer_caps, parse_emule_info(&payload2));
                let peer_udp = peer_caps.udp_port;
                peer_supports_large_files = peer_caps.supports_large_files;
                peer_supports_multipacket = peer_caps.supports_multi_packet;
                peer_supports_ext_multipacket = peer_caps.ext_multi_packet;
                peer_supports_file_ident = peer_caps.supports_file_ident;
                peer_supports_source_ex2 = peer_caps.supports_source_ex2;
                peer_source_exchange_ver = peer_caps.source_exchange_ver;
                peer_supports_aich = peer_caps.supports_aich;
                peer_extended_requests_ver = peer_caps.extended_requests_ver;
                peer_secure_ident_level = peer_caps.secure_ident_level;
                peer_is_ember = peer_caps.is_ember;
                peer_ember_hash = peer_caps.ember_hash;
                client_software_label = client_software_from_caps(&peer_caps);
                if !peer_caps.peer_name.is_empty() {
                    peer_name_label = peer_caps.peer_name.clone();
                }
                if peer_udp > 0 {
                    if let Some(sm) = &self.source_manager {
                        let mut sm = sm.write().await;
                        if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                            sm.register_source_full(self.file_hash, v4, self.source_addr.port(), peer_udp, peer_user_hash);
                        }
                    }
                }
                let emule_answer = build_emule_info(self.udp_port, self.obfuscation_enabled, Some(&self.ember_hash));
                write_packet_async(&mut writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &emule_answer).await?;
                debug!("Received peer OP_EMULEINFO, replied with OP_EMULEINFOANSWER");
                pending_secident_challenge = maybe_send_secident_challenge(
                    &mut writer,
                    self.credit_manager.as_ref(),
                    peer_user_hash,
                    self.source_addr,
                    peer_secure_ident_level,
                ).await?;
            } else {
                debug!("Peer skipped EmuleInfoAnswer (got proto=0x{proto2:02X} op=0x{opcode2:02X}), deferring");
                deferred_packet = Some((proto2, opcode2, payload2));
            }
        }

        // Handle secure identification packets that may arrive before file requests.
        // Be passive: store peer key material and answer explicit challenges.
        for _ in 0..3 {
            let (p, o, pl) = if let Some(pkt) = deferred_packet.take() {
                pkt
            } else {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    read_packet_async(&mut reader),
                ).await {
                    Ok(Ok(pkt)) => pkt,
                    _ => break,
                }
            };

            match (p, o) {
                (OP_EMULEPROT, OP_PUBLICKEY) if !pl.is_empty() => {
                    let key = if pl.len() >= 2 && pl[0] as usize == pl.len() - 1 {
                        pl[1..].to_vec()
                    } else {
                        pl
                    };
                    if let Some(cm) = &self.credit_manager {
                        let mut cm = cm.write().await;
                        cm.set_public_key(peer_user_hash, key);
                    }
                    if let Some((challenge, state)) = pending_peer_challenge.take() {
                        respond_to_secident_challenge(
                            &mut writer,
                            self.credit_manager.as_ref(),
                            state,
                            challenge,
                            self.source_addr,
                            peer_user_hash,
                            peer_secure_ident_level,
                            0u32,
                        ).await?;
                    }
                    if pending_secident_challenge.is_none() {
                        pending_secident_challenge = maybe_send_secident_challenge(
                            &mut writer,
                            self.credit_manager.as_ref(),
                            peer_user_hash,
                            self.source_addr,
                            peer_secure_ident_level,
                        ).await?;
                    }
                    debug!("Received peer's public key");
                }
                (OP_EMULEPROT, OP_SECIDENTSTATE) if pl.len() >= 5 => {
                    let state = pl[0];
                    let challenge = u32::from_le_bytes([pl[1], pl[2], pl[3], pl[4]]);
                    let missing_peer_key = if state >= 2 {
                        if let Some(cm) = &self.credit_manager {
                            let cm = cm.read().await;
                            !cm.has_public_key(&peer_user_hash)
                        } else {
                            true
                        }
                    } else {
                        false
                    };
                    if missing_peer_key {
                        pending_peer_challenge = Some((challenge, state));
                    } else {
                        respond_to_secident_challenge(
                            &mut writer,
                            self.credit_manager.as_ref(),
                            state,
                            challenge,
                            self.source_addr,
                            peer_user_hash,
                            peer_secure_ident_level,
                            0u32,
                        ).await?;
                    }
                    debug!("Responded to SecIdent challenge");
                }
                (OP_EMULEPROT, OP_SIGNATURE) if pl.len() >= 2 => {
                    handle_secident_signature(
                        self.credit_manager.as_ref(),
                        peer_user_hash,
                        &mut pending_secident_challenge,
                        self.source_addr,
                        peer_secure_ident_level,
                        &pl,
                        0u32,
                    ).await;
                }
                (OP_EMULEPROT, OP_EMULEINFOANSWER) | (OP_EMULEPROT, OP_EMULEINFO) => {
                    let mut peer_caps = initial_caps.clone();
                    merge_caps(&mut peer_caps, parse_emule_info(&pl));
                    let peer_udp = peer_caps.udp_port;
                    peer_supports_large_files = peer_caps.supports_large_files;
                    peer_supports_multipacket = peer_caps.supports_multi_packet;
                    peer_supports_ext_multipacket = peer_caps.ext_multi_packet;
                    peer_supports_file_ident = peer_caps.supports_file_ident;
                    peer_supports_source_ex2 = peer_caps.supports_source_ex2;
                    peer_source_exchange_ver = peer_caps.source_exchange_ver;
                    peer_supports_aich = peer_caps.supports_aich;
                    peer_extended_requests_ver = peer_caps.extended_requests_ver;
                    peer_secure_ident_level = peer_caps.secure_ident_level;
                    peer_is_ember = peer_caps.is_ember;
                    peer_ember_hash = peer_caps.ember_hash;
                    client_software_label = client_software_from_caps(&peer_caps);
                    if !peer_caps.peer_name.is_empty() {
                        peer_name_label = peer_caps.peer_name.clone();
                    }
                    if peer_udp > 0 {
                        if let Some(sm) = &self.source_manager {
                            let mut sm = sm.write().await;
                            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                sm.register_source_full(self.file_hash, v4, self.source_addr.port(), peer_udp, peer_user_hash);
                            }
                        }
                    }
                    if o == OP_EMULEINFO {
                        let emule_answer = build_emule_info(self.udp_port, self.obfuscation_enabled, Some(&self.ember_hash));
                        let _ = write_packet_async(&mut writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &emule_answer).await;
                        debug!("Received delayed peer OP_EMULEINFO, replied with OP_EMULEINFOANSWER");
                    } else {
                        debug!("Got delayed EmuleInfoAnswer");
                    }
                }
                (OP_EDONKEYHEADER, OP_ACCEPTUPLOADREQ) => {
                    early_upload_accept = true;
                    debug!("Received early AcceptUploadReq before file status");
                }
                (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE) if epx_packets_received < crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION => {
                    epx_packets_received += 1;
                    info!("Received early EPX from {} during pre-control ({} bytes)", self.source_addr, pl.len());
                    match crate::network::ember::parse_exchange_payload(&pl) {
                        Ok(result) if !result.files.is_empty() || !result.peers.is_empty() => {
                            let (epx_entries, aich_roots) = epx_result_to_entries(&result);
                            let epx_peers = result.peers.into_iter().map(|ep| (ep.ip, ep.tcp_port)).collect();
                            let _ = event_tx.send(DownloadEvent::EmberSources {
                                transfer_id: self.transfer_id.clone(),
                                entries: epx_entries,
                                aich_roots,
                                ember_peers: epx_peers,
                            }).await;
                        }
                        Ok(_) => {}
                        Err(e) => debug!("Failed to parse early EPX from {}: {e}", self.source_addr),
                    }
                }
                (OP_EMULEPROT, OP_EMBER_FRIEND_REQ) => {
                    if let Some(eh) = peer_ember_hash {
                        let nick = std::str::from_utf8(&pl).unwrap_or("").to_string();
                        info!("Received early friend request from {} (nick='{}')", self.source_addr, nick);
                        let _ = event_tx.send(DownloadEvent::EmberFriendRequest {
                            ember_hash: eh,
                            nickname: nick,
                            peer_ip: self.source_addr.ip().to_string(),
                            peer_port: self.source_addr.port(),
                        }).await;
                    }
                }
                _ => {
                    deferred_packet = Some((p, o, pl));
                    break;
                }
            }
        }

        // Ember Peer Exchange: if peer is a Ember client, send our source list
        if peer_is_ember {
            let epx_data = self.ember_payload.read().await.clone();
            if !epx_data.is_empty() {
                debug!("Sending Ember Peer Exchange to {} ({} bytes)", self.source_addr, epx_data.len());
                let _ = write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE, &*epx_data).await;
            }
            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                let peer_tcp = self.source_addr.port();
                if peer_tcp > 0 && !v4.is_private() && !v4.is_loopback() && !v4.is_link_local() {
                    let _ = event_tx.send(DownloadEvent::EmberPeerDiscovered {
                        ip: v4,
                        tcp_port: peer_tcp,
                    }).await;
                }
            }
        }

        let peer_is_friend = if let (Some(ref fh), Some(eh)) = (&self.friend_hashes, peer_ember_hash) {
            fh.read().await.contains(&eh)
        } else {
            false
        };
        if peer_is_ember && peer_is_friend {
            let nick_bytes = self.our_nickname.as_bytes();
            let _ = write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_FRIEND_REQ, nick_bytes).await;
        }
        if let (true, Some(eh)) = (peer_is_friend, peer_ember_hash) {
            let _ = event_tx.send(DownloadEvent::FriendSeen {
                ember_hash: eh,
                ip: self.source_addr.ip(),
                port: self.source_addr.port(),
            }).await;
        }
        let is_ember_friend = peer_is_ember && peer_is_friend;

        // Send file request in eMule order:
        // 1) OP_REQUESTFILENAME
        // 2) OP_SETREQFILEID (only needed for multipart files)
        let part_count = ed2k_part_count_for_size(self.file_size);
        let wire_part_count = ed2k_wire_part_count(self.file_size);
        let single_part = part_count <= 1;
        let file_req = build_file_request(&self.file_hash);
        let mut req_file_name_payload = file_req.clone();
        if peer_extended_requests_ver > 0 {
            req_file_name_payload.extend_from_slice(&(wire_part_count as u16).to_le_bytes());
            let bitmap_bytes = (wire_part_count + 7) / 8;
            req_file_name_payload.extend(std::iter::repeat_n(0u8, bitmap_bytes));
            if peer_extended_requests_ver > 1 {
                req_file_name_payload.extend_from_slice(&0u16.to_le_bytes());
            }
        }
        // eMule IsSourceRequestAllowed: throttle SX to once per 40 min per source
        let sx_allowed = if let Some(sm) = &self.source_manager {
            let sm = sm.read().await;
            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                sm.can_request_sources_for(&self.file_hash, v4, self.source_addr.port())
            } else { true }
        } else { true };

        if peer_supports_file_ident || peer_supports_ext_multipacket || peer_supports_multipacket {
            // eMule-style multipacket file request.
            let mut mp = Vec::with_capacity(64 + req_file_name_payload.len());
            if peer_supports_file_ident {
                FileIdentifier {
                    md4_hash: self.file_hash,
                    file_size: Some(self.file_size),
                    aich_hash: None,
                }
                .write_identifier(&mut mp);
            } else if peer_supports_ext_multipacket {
                mp.extend_from_slice(&self.file_hash);
                mp.extend_from_slice(&self.file_size.to_le_bytes()); // EXT: file size
            } else {
                mp.extend_from_slice(&self.file_hash);
            }
            mp.push(OP_REQUESTFILENAME);
            if peer_extended_requests_ver > 0 {
                mp.extend_from_slice(&(wire_part_count as u16).to_le_bytes());
                let bitmap_bytes = (wire_part_count + 7) / 8;
                mp.extend(std::iter::repeat_n(0u8, bitmap_bytes));
                if peer_extended_requests_ver > 1 {
                    mp.extend_from_slice(&0u16.to_le_bytes());
                }
            }
            if !single_part {
                mp.push(OP_SETREQFILEID);
            }
            if sx_allowed {
                if peer_supports_source_ex2 {
                    mp.push(OP_REQUESTSOURCES2);
                    mp.push(SOURCEEXCHANGE2_VERSION);
                    mp.extend_from_slice(&0u16.to_le_bytes());
                } else {
                    mp.push(OP_REQUESTSOURCES);
                }
            }
            if peer_supports_aich && !peer_supports_file_ident {
                mp.push(OP_AICHFILEHASHREQ);
            }
            let mp_opcode = if peer_supports_file_ident {
                OP_MULTIPACKET_EXT2
            } else if peer_supports_ext_multipacket {
                OP_MULTIPACKET_EXT
            } else {
                OP_MULTIPACKET
            };
            write_packet_async(&mut writer, OP_EMULEPROT, mp_opcode, &mp).await?;
            if sx_allowed {
                if let Some(sm) = &self.source_manager {
                    let mut sm = sm.write().await;
                    if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                        sm.mark_sx_sent(&self.file_hash, v4, self.source_addr.port());
                    }
                }
            }
        } else {
            write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_REQUESTFILENAME, &req_file_name_payload).await?;
            if !single_part {
                write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_SETREQFILEID, &file_req).await?;
            }
        }

        // Read FileStatus and FileName responses
        let mut got_status = single_part;
        let mut got_filename = false;
        let mut available_parts: Vec<bool> = if single_part {
            vec![true]
        } else {
            Vec::new()
        };

        for _ in 0..12 {
            let (proto, opcode, payload) = if let Some(pkt) = deferred_packet.take() {
                pkt
            } else {
                read_packet_with_timeout(&mut reader)
                    .await
                    .context("stage:file_status_wait")?
            };

            match (proto, opcode) {
                (OP_EDONKEYHEADER, OP_FILESTATUS) => {
                    let (hash, parts) = parse_file_status(&payload)?;
                    if hash != self.file_hash {
                        anyhow::bail!(
                            "peer sent FileStatus for wrong file: expected={} got={}",
                            hex::encode(self.file_hash),
                            hex::encode(hash)
                        );
                    }
                    if parts.is_empty() {
                        debug!("FileStatus: part_count=0 → peer has complete file ({} parts)", part_count);
                        available_parts = vec![true; part_count.max(1)];
                    } else {
                        debug!("FileStatus: {} parts", parts.len());
                        let mut padded = parts;
                        if padded.len() < part_count {
                            padded.resize(part_count, false);
                        }
                        available_parts = padded;
                    }
                    got_status = true;
                }
                (OP_EDONKEYHEADER, OP_REQFILENAMEANSWER) => {
                    got_filename = true;
                    debug!("Got filename answer");
                }
                (OP_EDONKEYHEADER, OP_FILEREQANSNOFIL) => {
                    anyhow::bail!("peer does not have the file");
                }
                (OP_EDONKEYHEADER, OP_ACCEPTUPLOADREQ) => {
                    early_upload_accept = true;
                    debug!("Received early AcceptUploadReq during file-status wait");
                }
                (OP_EMULEPROT, OP_EMULEINFOANSWER) | (OP_EMULEPROT, OP_EMULEINFO) => {
                    let mut peer_caps = initial_caps.clone();
                    merge_caps(&mut peer_caps, parse_emule_info(&payload));
                    let peer_udp = peer_caps.udp_port;
                    peer_supports_large_files = peer_caps.supports_large_files;
                    peer_is_ember = peer_caps.is_ember;
                    peer_ember_hash = peer_caps.ember_hash;
                    client_software_label = client_software_from_caps(&peer_caps);
                    if !peer_caps.peer_name.is_empty() {
                        peer_name_label = peer_caps.peer_name.clone();
                    }
                    if peer_udp > 0 {
                        if let Some(sm) = &self.source_manager {
                            let mut sm = sm.write().await;
                            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                sm.register_source_full(self.file_hash, v4, self.source_addr.port(), peer_udp, peer_user_hash);
                            }
                        }
                    }
                    if opcode == OP_EMULEINFO {
                        let emule_answer = build_emule_info(self.udp_port, self.obfuscation_enabled, Some(&self.ember_hash));
                        let _ = write_packet_async(&mut writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &emule_answer).await;
                        debug!("Received peer OP_EMULEINFO during file-status wait, replied");
                    } else {
                        debug!("Ignoring delayed EmuleInfoAnswer during file-status wait");
                    }
                }
                (OP_EMULEPROT, OP_PUBLICKEY) if !payload.is_empty() => {
                    let key = if payload.len() >= 2 && payload[0] as usize == payload.len() - 1 {
                        payload[1..].to_vec()
                    } else {
                        payload.clone()
                    };
                    if let Some(cm) = &self.credit_manager {
                        let mut cm = cm.write().await;
                        cm.set_public_key(peer_user_hash, key);
                    }
                    if pending_secident_challenge.is_none() {
                        pending_secident_challenge = maybe_send_secident_challenge(
                            &mut writer,
                            self.credit_manager.as_ref(),
                            peer_user_hash,
                            self.source_addr,
                            peer_secure_ident_level,
                        ).await?;
                    }
                }
                (OP_EMULEPROT, OP_SECIDENTSTATE) if payload.len() >= 5 => {
                    respond_to_secident_challenge(
                        &mut writer,
                        self.credit_manager.as_ref(),
                        payload[0],
                        u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]),
                        self.source_addr,
                        peer_user_hash,
                        peer_secure_ident_level,
                        0u32,
                    ).await?;
                }
                (OP_EMULEPROT, OP_SIGNATURE) if payload.len() >= 2 => {
                    handle_secident_signature(
                        self.credit_manager.as_ref(),
                        peer_user_hash,
                        &mut pending_secident_challenge,
                        self.source_addr,
                        peer_secure_ident_level,
                        &payload,
                        0u32,
                    ).await;
                }
                (OP_EMULEPROT, OP_MULTIPACKETANSWER)
                | (OP_EMULEPROT, OP_MULTIPACKETANSWER_EXT2) => {
                    if let Ok(mp) = parse_multipacket_answer(&payload, opcode) {
                        let local_ident = FileIdentifier {
                            md4_hash: self.file_hash,
                            file_size: Some(self.file_size),
                            aich_hash: None,
                        };
                        if mp.file_hash != self.file_hash
                            || mp.file_identifier.as_ref().map(|id| !local_ident.compare_relaxed(id)).unwrap_or(false)
                        {
                            continue;
                        }
                        if mp.no_file {
                            anyhow::bail!("peer does not have the file");
                        }
                        if let Some(parts) = mp.file_status {
                            if parts.is_empty() {
                                debug!("FileStatus via MultiPacket: part_count=0 → peer has complete file ({} parts)", part_count);
                                available_parts = vec![true; part_count.max(1)];
                            } else {
                                debug!("FileStatus via MultiPacket: {} parts", parts.len());
                                let mut padded = parts;
                                if padded.len() < part_count {
                                    padded.resize(part_count, false);
                                }
                                available_parts = padded;
                            }
                            got_status = true;
                        }
                        if mp.file_name.is_some() {
                            got_filename = true;
                            debug!("Got filename answer via MultiPacket");
                        }
                    }
                }
                (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE) => {
                    if epx_packets_received >= crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION {
                        debug!("Ignoring excess EPX packet from {}", self.source_addr);
                    } else {
                        epx_packets_received += 1;
                        match crate::network::ember::parse_exchange_payload(&payload) {
                            Ok(result) if !result.files.is_empty() || !result.peers.is_empty() => {
                                info!("Received Ember Peer Exchange from {} ({} files, {} peers)", self.source_addr, result.files.len(), result.peers.len());
                                let (epx_entries, aich_roots) = epx_result_to_entries(&result);
                                let ember_peers = result.peers.into_iter().map(|p| (p.ip, p.tcp_port)).collect();
                                let _ = event_tx
                                    .send(DownloadEvent::EmberSources {
                                        transfer_id: self.transfer_id.clone(),
                                        entries: epx_entries,
                                        aich_roots,
                                        ember_peers,
                                    })
                                    .await;
                            }
                            Ok(_) => {}
                            Err(e) => debug!("Failed to parse Ember exchange from {}: {e}", self.source_addr),
                        }
                    }
                }
                (OP_EMULEPROT, OP_EMBER_FRIEND_REQ) if peer_is_ember => {
                    if let Some(eh) = peer_ember_hash {
                        let nick = std::str::from_utf8(&payload).unwrap_or("").to_string();
                        let _ = event_tx.send(DownloadEvent::EmberFriendRequest {
                            ember_hash: eh,
                            nickname: nick,
                            peer_ip: self.source_addr.ip().to_string(),
                            peer_port: self.source_addr.port(),
                        }).await;
                    }
                }
                (OP_EMULEPROT, OP_EMBER_CHAT_MSG) if is_ember_friend && payload.len() <= 4096 => {
                    if let Some(eh) = peer_ember_hash {
                        if let Ok(msg) = std::str::from_utf8(&payload) {
                            let _ = event_tx.send(DownloadEvent::EmberChatMessage {
                                ember_hash: eh,
                                message: msg.to_string(),
                            }).await;
                        }
                    }
                }
                _ => {
                    debug!("Ignoring packet proto=0x{proto:02X} op=0x{opcode:02X}");
                }
            }

            if got_status {
                break;
            }
        }

        if !got_status && (got_filename || early_upload_accept) {
            // eMule-compatible fallback: some peers answer filename but omit FileStatus.
            // Continue optimistically with all parts potentially available.
            available_parts = vec![true; part_count.max(1)];
            got_status = true;
            debug!("Proceeding without FileStatus (filename/accept fallback)");
        }

        if !got_status {
            anyhow::bail!("never received FileStatus");
        }

        let src_avail_parts: Option<u32> = Some(available_parts.iter().filter(|&&p| p).count() as u32);
        let src_total_parts: Option<u32> = Some(available_parts.len() as u32);

        // Request part hashset for verification
        if peer_supports_file_ident {
            let hashset_req2 = build_hashset_request2(&self.file_hash, self.file_size, None, true, false);
            write_packet_async(&mut writer, OP_EMULEPROT, OP_HASHSETREQUEST2, &hashset_req2).await?;
        } else {
            let hashset_req = build_hashset_request(&self.file_hash);
            write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_HASHSETREQ, &hashset_req).await?;
        }

        let mut part_hashes: Vec<[u8; 16]> = Vec::new();
        let mut aich_master_hash: Option<[u8; 20]> = None;
        // Try to read hashset answer. The peer may send other packets
        // (SecIdent, EmuleInfo) before the hashset, so read up to 5 packets.
        for _hs_attempt in 0..5u32 {
            match read_packet_with_timeout(&mut reader)
                .await
                .context("stage:hashset_wait")
            {
                Ok((proto, opcode, payload)) => {
                    if proto == OP_EDONKEYHEADER && opcode == OP_HASHSETANSWER {
                        match parse_hashset_answer(&payload) {
                            Ok((_hash, hashes)) => {
                                if verify_hashset(&self.file_hash, &hashes, self.file_size) {
                                    debug!("Got verified hashset with {} part hashes", hashes.len());
                                    part_hashes = hashes;
                                } else {
                                    warn!("Hashset verification failed - combined hash doesn't match file hash");
                                }
                            }
                            Err(e) => debug!("Failed to parse hashset answer: {e}"),
                        }
                        break;
                    } else if proto == OP_EMULEPROT && opcode == OP_HASHSETANSWER2 {
                        match parse_hashset_answer2(&payload) {
                            Ok(resp) => {
                                let local_ident = FileIdentifier {
                                    md4_hash: self.file_hash,
                                    file_size: Some(self.file_size),
                                    aich_hash: None,
                                };
                                if !local_ident.compare_relaxed(&resp.identifier) {
                                    anyhow::bail!("hashsetanswer2 file identifier mismatch");
                                }
                                if let (Some(root), Some(part_hashes)) =
                                    (resp.aich_master_hash, resp.aich_part_hashes.as_ref())
                                {
                                    aich_master_hash = Some(root);
                                    debug!(
                                        "Got HashSet2 AICH data: master={}, parts={}",
                                        hex::encode(root),
                                        part_hashes.len()
                                    );
                                }
                                if let Some(hashes) = resp.md4_hashes {
                                    if verify_hashset(&self.file_hash, &hashes, self.file_size) {
                                        debug!("Got verified hashset2 with {} part hashes", hashes.len());
                                        part_hashes = hashes;
                                    } else {
                                        warn!("Hashset2 verification failed - combined hash doesn't match file hash");
                                    }
                                }
                            }
                            Err(e) => debug!("Failed to parse hashset answer2: {e}"),
                        }
                        break;
                    } else if proto == OP_EDONKEYHEADER && opcode == OP_ACCEPTUPLOADREQ {
                        early_upload_accept = true;
                        debug!("Received AcceptUploadReq while waiting for hashset — stopping hashset wait");
                        break;
                    } else {
                        debug!("Waiting for hashset, got proto=0x{proto:02X} op=0x{opcode:02X} — skipping");
                    }
                }
                Err(e) => {
                    debug!("No hashset answer (peer may not support it): {e}");
                    break;
                }
            }
        }

        // Request source exchange only when not already sent in multipacket, and throttled
        if !(peer_supports_file_ident || peer_supports_ext_multipacket || peer_supports_multipacket) && sx_allowed {
            if peer_supports_source_ex2 {
                let mut sx2_req = Vec::with_capacity(19);
                sx2_req.push(SOURCEEXCHANGE2_VERSION);
                sx2_req.extend_from_slice(&0u16.to_le_bytes());
                sx2_req.extend_from_slice(&self.file_hash);
                write_packet_async(&mut writer, OP_EMULEPROT, OP_REQUESTSOURCES2, &sx2_req).await?;
            } else {
                let sx_req = build_file_request(&self.file_hash);
                write_packet_async(&mut writer, OP_EMULEPROT, OP_REQUESTSOURCES, &sx_req).await?;
            }
            if let Some(sm) = &self.source_manager {
                let mut sm = sm.write().await;
                if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                    sm.mark_sx_sent(&self.file_hash, v4, self.source_addr.port());
                }
            }
        }

        if early_upload_accept {
            debug!("Using early AcceptUploadReq without sending StartUploadReq");
            self.emit_source_detail_parts(event_tx, "transferring", None, 0, 0, &client_software_label, &peer_name_label, src_avail_parts, src_total_parts).await;
            let _ = event_tx
                .send(DownloadEvent::SourcesUpdate {
                    transfer_id: self.transfer_id.clone(),
                    total: 1,
                    active: 1,
                    queued: 0,
                })
                .await;
        } else {
            // Request upload slot
            let upload_req = build_file_request(&self.file_hash);
            write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_STARTUPLOADREQ, &upload_req).await?;

            let _ = event_tx
                .send(DownloadEvent::SourcesUpdate {
                    transfer_id: self.transfer_id.clone(),
                    total: 1,
                    active: 0,
                    queued: 1,
                })
                .await;

            // Wait for AcceptUploadReq. The uploader decides when to grant a slot;
            // we simply keep the connection open and listen. Re-requesting too
            // aggressively gets clients penalised by eMule servers.
            let queue_start = std::time::Instant::now();
            self.emit_source_detail_parts(event_tx, "queued", None, 0, 0, &client_software_label, &peer_name_label, src_avail_parts, src_total_parts).await;

            loop {
                self.check_control().await?;

                let qwait = self.ed2k_limits.queue_wait_secs;
                if queue_start.elapsed().as_secs() > qwait {
                    anyhow::bail!("stage:queue_wait timed out waiting for upload slot after {qwait}s");
                }

                // Use a longer timeout while queued — the uploader will push
                // OP_ACCEPTUPLOADREQ when a slot opens. We use the full queue
                // wait budget as the read timeout so we don't time out early.
                let remaining = qwait - queue_start.elapsed().as_secs().min(qwait);
                let read_timeout = remaining.max(30);

                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(read_timeout),
                    read_packet_async(&mut reader),
                )
                .await;

                let (proto, opcode, payload) = match result {
                    Ok(Ok(p)) => p,
                    Ok(Err(e)) => anyhow::bail!("stage:queue_detached connection lost while queued: {e}"),
                    Err(_) => {
                        anyhow::bail!("stage:queue_wait timed out waiting for upload slot after {qwait}s");
                    }
                };

                if proto == OP_EDONKEYHEADER && opcode == OP_ACCEPTUPLOADREQ {
                    debug!("Upload accepted");
                    self.emit_source_detail_parts(event_tx, "transferring", None, 0, 0, &client_software_label, &peer_name_label, src_avail_parts, src_total_parts).await;
                    let _ = event_tx
                        .send(DownloadEvent::SourcesUpdate {
                            transfer_id: self.transfer_id.clone(),
                            total: 1,
                            active: 1,
                            queued: 0,
                        })
                        .await;
                    break;
                }

                if proto == OP_EMULEPROT && opcode == OP_QUEUEFULL && payload.is_empty() {
                    self.emit_source_detail_parts(event_tx, "queue_full", None, 0, 0, &client_software_label, &peer_name_label, src_avail_parts, src_total_parts).await;
                    anyhow::bail!("stage:queue_wait peer queue is full");
                }

                if proto == OP_EMULEPROT && opcode == OP_QUEUERANKING && payload.len() >= 2 {
                    let rank = u16::from_le_bytes([payload[0], payload[1]]);
                    info!(
                        "Queued at position {} on peer {}",
                        rank, self.source_addr
                    );
                    self.emit_source_detail_parts(event_tx, "queued", Some(rank as u32), 0, 0, &client_software_label, &peer_name_label, src_avail_parts, src_total_parts).await;
                    continue;
                }

                if proto == OP_EDONKEYHEADER && opcode == OP_QUEUERANK && payload.len() >= 4 {
                    let rank = u32::from_le_bytes([
                        payload[0], payload[1], payload[2], payload[3],
                    ]);
                    info!(
                        "Queued at position {} on peer {} (legacy)",
                        rank, self.source_addr
                    );
                    self.emit_source_detail_parts(event_tx, "queued", Some(rank), 0, 0, &client_software_label, &peer_name_label, src_avail_parts, src_total_parts).await;
                    continue;
                }

                if proto == OP_EMULEPROT && opcode == OP_ANSWERSOURCES && payload.len() >= 18 {
                    match parse_answer_sources(&payload, peer_source_exchange_ver) {
                        Ok((version, answer_hash, entries)) if answer_hash == self.file_hash => {
                            let mut sx_count = 0u32;
                            let mut sx_entries: Vec<SourceExchangeEntry> = Vec::new();
                            for entry in entries {
                                if entry.tcp_port == 0 {
                                    continue;
                                }
                                if entry.source_id < 16_777_216 {
                                    debug!("SX1: skipping Low-ID source {} (server {:08X}:{})", entry.source_id, entry.server_ip, entry.server_port);
                                    continue;
                                }
                                let ip = source_exchange_id_to_ipv4(version, entry.source_id);
                                if is_filtered_source_ip(&ip) || self.is_sx_source_rejected(&ip, entry.tcp_port) {
                                    continue;
                                }
                                let uh = entry.user_hash.unwrap_or([0u8; 16]);
                                let co = entry.crypt_options.unwrap_or(0);
                                if let Some(sm) = &self.source_manager {
                                    let mut sm = sm.write().await;
                                    sm.register_source_full_server(
                                        self.file_hash, ip, entry.tcp_port, 0, entry.server_ip, entry.server_port, uh, co,
                                    );
                                }
                                sx_entries.push(SourceExchangeEntry {
                                    ip, tcp_port: entry.tcp_port, user_hash: uh, crypt_options: co,
                                });
                                sx_count += 1;
                            }
                            if sx_count > 0 {
                                debug!("Legacy source exchange: registered {sx_count} new sources from {}", self.source_addr);
                                let _ = event_tx.send(DownloadEvent::SourceExchange {
                                    transfer_id: self.transfer_id.clone(),
                                    file_hash: self.file_hash,
                                    sources: sx_entries,
                                }).await;
                            }
                        }
                        Ok((_version, answer_hash, _)) => {
                            debug!(
                                "Ignoring OP_ANSWERSOURCES from {} for different file {}",
                                self.source_addr,
                                hex::encode(answer_hash)
                            );
                        }
                        Err(e) => debug!("Failed to parse OP_ANSWERSOURCES from {}: {e}", self.source_addr),
                    }
                    continue;
                }

                if proto == OP_EMULEPROT && opcode == OP_ANSWERSOURCES2 && payload.len() >= 19 {
                    match parse_answer_sources2(&payload) {
                        Ok((version, answer_hash, entries)) if answer_hash == self.file_hash => {
                            let mut sx_count = 0u32;
                            let mut sx_entries: Vec<SourceExchangeEntry> = Vec::new();
                            for entry in entries {
                                if entry.tcp_port == 0 {
                                    continue;
                                }
                                if entry.source_id < 16_777_216 {
                                    debug!("SX2: skipping Low-ID source {} (server {:08X}:{})", entry.source_id, entry.server_ip, entry.server_port);
                                    continue;
                                }
                                let ip = source_exchange_id_to_ipv4(version, entry.source_id);
                                if is_filtered_source_ip(&ip) || self.is_sx_source_rejected(&ip, entry.tcp_port) {
                                    continue;
                                }
                                if entry.server_ip != 0 {
                                    debug!("SX2 source {} advertises server {:08X}:{}", ip, entry.server_ip, entry.server_port);
                                }
                                let uh = entry.user_hash.unwrap_or([0u8; 16]);
                                let co = entry.crypt_options.unwrap_or(0);
                                if let Some(sm) = &self.source_manager {
                                    let mut sm = sm.write().await;
                                    sm.register_source_full_server(
                                        self.file_hash, ip, entry.tcp_port, 0,
                                        entry.server_ip, entry.server_port, uh, co,
                                    );
                                }
                                sx_entries.push(SourceExchangeEntry {
                                    ip, tcp_port: entry.tcp_port, user_hash: uh, crypt_options: co,
                                });
                                sx_count += 1;
                            }
                            if sx_count > 0 {
                                debug!("Source exchange: registered {sx_count} new sources from {}", self.source_addr);
                                let _ = event_tx.send(DownloadEvent::SourceExchange {
                                    transfer_id: self.transfer_id.clone(),
                                    file_hash: self.file_hash,
                                    sources: sx_entries,
                                }).await;
                            }
                        }
                        Ok((_version, answer_hash, _)) => {
                            debug!(
                                "Ignoring OP_ANSWERSOURCES2 from {} for different file {}",
                                self.source_addr,
                                hex::encode(answer_hash)
                            );
                        }
                        Err(e) => debug!("Failed to parse OP_ANSWERSOURCES2 from {}: {e}", self.source_addr),
                    }
                    continue;
                }

                if proto == OP_EDONKEYHEADER && opcode == OP_OUTOFPARTREQS {
                    info!("Peer rejected with OutOfPartReqs, will retry later");
                    self.emit_source_detail_parts(event_tx, "no_needed_parts", None, 0, 0, &client_software_label, &peer_name_label, src_avail_parts, src_total_parts).await;
                    anyhow::bail!("peer has no free upload slots (OutOfPartReqs)");
                }

                debug!("Waiting for accept, got proto=0x{proto:02X} op=0x{opcode:02X}");
            }
        }

        let max_dl = self.ed2k_limits.max_download_bytes;
        if self.file_size > max_dl {
            anyhow::bail!(
                "file size {} exceeds maximum allowed ({})",
                self.file_size,
                max_dl
            );
        }

        // Ensure download directories exist:
        //   <download_dir>/Temp/     -- .part files during download
        //   <download_dir>/Downloads/ -- completed files
        let temp_dir = self.download_dir.join("Temp");
        let completed_dir = self.download_dir.join("Downloads");
        tokio::fs::create_dir_all(&temp_dir).await?;
        tokio::fs::create_dir_all(&completed_dir).await?;

        let safe_name = crate::security::sanitize_filename(&self.file_name);
        let part_path = temp_dir.join(format!("{}.part", self.transfer_id));
        let final_path = completed_dir.join(&safe_name);

        let mut tracker = PartTracker::new(self.file_size, &part_path);
        tracker.set_file_hash(self.file_hash);
        tracker.set_file_name(&self.file_name);
        if !part_hashes.is_empty() {
            tracker.set_part_hashes(part_hashes.clone());
        }

        let output: Arc<std::sync::Mutex<std::fs::File>> = {
            let pp = part_path.clone();
            let fs = self.file_size;
            let completed_bytes = tracker.completed_bytes();
            let completed_parts = tracker.completed_count();
            let total_parts = tracker.part_count;
            Arc::new(std::sync::Mutex::new(
                tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
                    let existing_len = if pp.exists() {
                        std::fs::metadata(&pp)?.len()
                    } else {
                        0
                    };
                    // Never truncate a non-empty .part when .part.met reports 0 completed bytes
                    // (e.g. corrupt/missing metadata) — that would destroy recoverable data.
                    let resuming = completed_bytes > 0 || existing_len > 0;
                    if resuming {
                        if completed_bytes > 0 {
                            info!(
                                "Resuming download: {completed_parts}/{total_parts} parts complete"
                            );
                        } else {
                            warn!(
                                "Preserving non-empty .part ({existing_len} bytes) while resume metadata shows no completed bytes — \
                                 .part.met may be missing or corrupt"
                            );
                        }
                        let f = std::fs::OpenOptions::new()
                            .create(true)
                            .write(true)
                            .read(true)
                            .open(&pp)?;
                        if fs > 0 && f.metadata()?.len() != fs {
                            f.set_len(fs)?;
                        }
                        Ok(f)
                    } else {
                        let f = std::fs::OpenOptions::new()
                            .create(true)
                            .write(true)
                            .read(true)
                            .truncate(true)
                            .open(&pp)?;
                        if fs > 0 {
                            f.set_len(fs)?;
                        }
                        Ok(f)
                    }
                })
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??,
            ))
        };

        let mut downloaded: u64 = tracker.completed_bytes();

        // Download needed parts with retry for hash-failed parts.
        // eMule-style adaptive pipelining: sends 1-3 OP_REQUESTPARTS_I64 packets
        // simultaneously based on connection speed, keeping the peer's upload pipe full.
        const MAX_BLOCKS_PER_REQUEST: usize = 3;
        let max_part_rounds = self.ed2k_limits.part_retry_rounds;
        let mut peer_out_of_parts = false;
        let mut measured_speed: u64 = 0;
        let mut speed_measure_start = std::time::Instant::now();
        let mut speed_measure_bytes: u64 = 0;
        let mut last_periodic_save = std::time::Instant::now();
        const PERIODIC_SAVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
        let mut last_epx_resend = std::time::Instant::now();
        let mut last_epx_generation = self.ember_payload_generation.load(std::sync::atomic::Ordering::Relaxed);
        const EPX_RESEND_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

        for retry_round in 0..=max_part_rounds {
            let mut needed = tracker.needed_parts(&available_parts);
            if needed.is_empty() {
                break;
            }

            // eMule-style preview priority: move first and last parts to front
            if self.control.is_preview_priority() && needed.len() > 1 {
                let last_part = tracker.part_count.saturating_sub(1);
                let mut front = Vec::new();
                if let Some(pos) = needed.iter().position(|&p| p == 0) {
                    front.push(needed.remove(pos));
                }
                if last_part > 0 {
                    if let Some(pos) = needed.iter().position(|&p| p == last_part) {
                        front.push(needed.remove(pos));
                    }
                }
                front.extend(needed);
                needed = front;
            }
            if retry_round > 0 {
                warn!(
                    "Retry round {}/{} for {} hash-failed parts",
                    retry_round, max_part_rounds, needed.len()
                );
            }

            for part_idx in needed {
                if peer_out_of_parts {
                    break;
                }
                self.check_control().await?;
                let mut aich_recovery_data: Option<([u8; 20], Vec<u8>)> = None;

                let (part_start, part_end) = tracker.part_range(part_idx);

                // Request only the missing byte ranges within this part, like eMule's gap-based requests.
                let all_blocks: Vec<(u64, u64)> = tracker
                    .gap_list()
                    .iter()
                    .filter_map(|&(gs, ge)| {
                        let start = gs.max(part_start);
                        let end = ge.min(part_end);
                        (start < end).then_some((start, end))
                    })
                    .flat_map(|(start, end)| {
                        let mut blocks = Vec::new();
                        let mut cursor = start;
                        while cursor < end {
                            let chunk_end = (cursor + EMBLOCKSIZE).min(end);
                            blocks.push((cursor, chunk_end));
                            cursor = chunk_end;
                        }
                        blocks
                    })
                    .collect();

                // Group blocks into request batches of 3 (OP_REQUESTPARTS_I64 limit)
                let batches: Vec<Vec<(u64, u64)>> = all_blocks
                    .chunks(MAX_BLOCKS_PER_REQUEST)
                    .map(|c| c.to_vec())
                    .collect();

                let max_outstanding = outstanding_requests_for_speed_with_remaining(
                    measured_speed,
                    tracker.remaining_count(),
                    tracker.remaining_gap_bytes(),
                );
                let mut sent_idx: usize = 0;
                let mut total_sent_bytes: u64 = 0;
                let mut total_received: u64 = 0;
                let mut consecutive_bad_blocks: u32 = 0;
                const MAX_CONSECUTIVE_BAD_BLOCKS: u32 = 5;

                // Match eMule: only use I64 when offsets actually exceed 32-bit range
                let has_large_offsets = all_blocks.iter().any(|&(_, end)| end > u32::MAX as u64);
                let needs_i64 = peer_supports_large_files && has_large_offsets;

                // If blocks exceed 4 GiB but the peer doesn't support large files,
                // filter them out to avoid sending (0,0) clamped garbage requests.
                if has_large_offsets && !peer_supports_large_files {
                    warn!(
                        "Skipping part {} — offsets exceed 4 GiB but peer lacks large-file support",
                        part_idx
                    );
                    continue;
                }

                // Send initial batch of requests to fill the pipeline
                while sent_idx < batches.len() && sent_idx < max_outstanding {
                    let batch = &batches[sent_idx];
                    let (req_payload, req_proto, req_op) = if needs_i64 {
                        (build_request_parts_i64(&self.file_hash, batch), OP_EMULEPROT, OP_REQUESTPARTS_I64)
                    } else {
                        (build_request_parts(&self.file_hash, batch), OP_EDONKEYHEADER, OP_REQUESTPARTS)
                    };
                    write_packet_async(
                        &mut writer,
                        req_proto,
                        req_op,
                        &req_payload,
                    )
                    .await?;
                    total_sent_bytes += batch.iter().map(|(s, e)| e - s).sum::<u64>();
                    sent_idx += 1;
                }

                // Track how many blocks received per request for pipeline refill
                let mut blocks_received_in_current_req: usize = 0;
                let mut completed_reqs: usize = 0;
                let mut pending_compressed: HashMap<u64, PendingCompressedBlock> = HashMap::new();
                let data_loop_start = std::time::Instant::now();
                let mut got_any_data = false;
                const INITIAL_DATA_TIMEOUT_SECS: u64 = 60;

                // Receive loop: process blocks and refill pipeline as requests complete
                while total_received < total_sent_bytes {
                    if peer_out_of_parts {
                        break;
                    }
                    self.check_control().await?;

                    // Periodic EPX re-send: if payload has been rebuilt and 5min elapsed
                    if peer_is_ember && last_epx_resend.elapsed() >= EPX_RESEND_INTERVAL {
                        let current_gen = self.ember_payload_generation.load(std::sync::atomic::Ordering::Relaxed);
                        if current_gen != last_epx_generation {
                            let epx_data = self.ember_payload.read().await.clone();
                            if !epx_data.is_empty() {
                                debug!("Re-sending EPX to {} (gen {}->{}, {} bytes)", self.source_addr, last_epx_generation, current_gen, epx_data.len());
                                let _ = write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE, &*epx_data).await;
                            }
                            last_epx_generation = current_gen;
                        }
                        last_epx_resend = std::time::Instant::now();
                    }

                    let read_timeout = if got_any_data {
                        std::time::Duration::from_secs(READ_TIMEOUT_SECS)
                    } else {
                        let elapsed = data_loop_start.elapsed();
                        let budget = std::time::Duration::from_secs(INITIAL_DATA_TIMEOUT_SECS);
                        budget.saturating_sub(elapsed).max(std::time::Duration::from_secs(1))
                    };

                    let (proto, opcode, payload) = match tokio::time::timeout(
                        read_timeout,
                        read_packet_async(&mut reader),
                    ).await {
                        Ok(Ok(pkt)) => pkt,
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_) => {
                            let _ = write_packet_async(
                                &mut writer, OP_EDONKEYHEADER, OP_CANCELTRANSFER, &[],
                            ).await;
                            if !got_any_data {
                                warn!("Source {} accepted transfer but sent no data in {}s — disconnecting",
                                    self.source_addr, INITIAL_DATA_TIMEOUT_SECS);
                                anyhow::bail!("peer accepted transfer but sent no data in {}s", INITIAL_DATA_TIMEOUT_SECS);
                            } else {
                                anyhow::bail!("stage:data_wait download timeout: no data for {}s", READ_TIMEOUT_SECS);
                            }
                        }
                    };

                    match (proto, opcode) {
                        (OP_EMULEPROT, OP_SENDINGPART_I64)
                        | (OP_EDONKEYHEADER, OP_SENDINGPART) => {
                            let (hash, start, end, data) =
                                if opcode == OP_SENDINGPART_I64 {
                                    parse_sending_part_i64(&payload)?
                                } else {
                                    parse_sending_part_32(&payload)?
                                };
                            if hash != self.file_hash {
                                anyhow::bail!(
                                    "peer sent SENDINGPART for wrong file: expected={} got={}",
                                    hex::encode(self.file_hash),
                                    hex::encode(hash)
                                );
                            }

                            if start >= end || end > self.file_size || data.len() != (end - start) as usize {
                                consecutive_bad_blocks += 1;
                                warn!("Invalid block offsets: start={start}, end={end}, data_len={}, file_size={} (bad streak: {consecutive_bad_blocks})", data.len(), self.file_size);
                                if consecutive_bad_blocks >= MAX_CONSECUTIVE_BAD_BLOCKS {
                                    anyhow::bail!("peer sent {consecutive_bad_blocks} consecutive invalid blocks, disconnecting");
                                }
                                continue;
                            }
                            consecutive_bad_blocks = 0;
                            let piece_len = end - start;
                            self.acquire_download_bandwidth(piece_len).await;

                            {
                                let out = output.clone();
                                let buf = data.to_vec();
                                tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                                    let mut f = out.lock().map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "file lock poisoned"))?;
                                    f.seek(std::io::SeekFrom::Start(start))?;
                                    f.write_all(&buf)?;
                                    Ok(())
                                }).await.map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;
                            }

                            // Update byte-level gap tracker for mid-part resume
                            tracker.fill_range(start, end);

                            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                let _ = event_tx
                                    .send(DownloadEvent::DataReceived {
                                        file_hash: self.file_hash,
                                        start,
                                        end,
                                        sender_ip: v4,
                                    })
                                    .await;
                            }

                            if !got_any_data {
                                info!("Source {} first data received for part {} ({} bytes)", self.source_addr, part_idx, piece_len);
                                got_any_data = true;
                            }
                            total_received += piece_len;
                            downloaded += piece_len;
                            blocks_received_in_current_req += 1;
                            speed_measure_bytes += piece_len;

                            if let Some(cm) = &self.credit_manager {
                                let mut cm = cm.write().await;
                                cm.add_downloaded(peer_user_hash, piece_len);
                            }

                            let _ = event_tx
                                .send(DownloadEvent::Progress {
                                    transfer_id: self.transfer_id.clone(),
                                    downloaded: downloaded.min(self.file_size),
                                    total: self.file_size,
                                })
                                .await;
                        }
                        (OP_EMULEPROT, OP_COMPRESSEDPART_I64)
                        | (OP_EMULEPROT, OP_COMPRESSEDPART) => {
                            let (hash, start, compressed_total_size, compressed) =
                                if opcode == OP_COMPRESSEDPART_I64 {
                                    parse_compressed_part_i64(&payload)?
                                } else {
                                    parse_compressed_part_32(&payload)?
                                };
                            if hash != self.file_hash {
                                anyhow::bail!(
                                    "peer sent COMPRESSEDPART for wrong file: expected={} got={}",
                                    hex::encode(self.file_hash),
                                    hex::encode(hash)
                                );
                            }

                            let Some(decompressed) = append_compressed_chunk(
                                &mut pending_compressed,
                                start,
                                compressed_total_size,
                                compressed,
                            )? else {
                                continue;
                            };

                            let piece_len = decompressed.len() as u64;
                            if start.saturating_add(piece_len) > self.file_size {
                                consecutive_bad_blocks += 1;
                                warn!("Compressed block exceeds file size: start={start}, len={piece_len}, file_size={} (bad streak: {consecutive_bad_blocks})", self.file_size);
                                if consecutive_bad_blocks >= MAX_CONSECUTIVE_BAD_BLOCKS {
                                    anyhow::bail!("peer sent {consecutive_bad_blocks} consecutive invalid blocks, disconnecting");
                                }
                                continue;
                            }
                            consecutive_bad_blocks = 0;
                            self.acquire_download_bandwidth(piece_len).await;

                            {
                                let out = output.clone();
                                tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                                    let mut f = out.lock().map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "file lock poisoned"))?;
                                    f.seek(std::io::SeekFrom::Start(start))?;
                                    f.write_all(&decompressed)?;
                                    Ok(())
                                }).await.map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;
                            }
                            tracker.fill_range(start, start + piece_len);

                            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                let _ = event_tx
                                    .send(DownloadEvent::DataReceived {
                                        file_hash: self.file_hash,
                                        start,
                                        end: start + piece_len,
                                        sender_ip: v4,
                                    })
                                    .await;
                            }

                            if !got_any_data {
                                info!("Source {} first compressed data received for part {} ({} bytes)", self.source_addr, part_idx, piece_len);
                                got_any_data = true;
                            }
                            total_received += piece_len;
                            downloaded += piece_len;
                            blocks_received_in_current_req += 1;
                            speed_measure_bytes += piece_len;

                            if let Some(cm) = &self.credit_manager {
                                let mut cm = cm.write().await;
                                cm.add_downloaded(peer_user_hash, piece_len);
                            }

                            let _ = event_tx
                                .send(DownloadEvent::Progress {
                                    transfer_id: self.transfer_id.clone(),
                                    downloaded: downloaded.min(self.file_size),
                                    total: self.file_size,
                                })
                                .await;
                        }
                        (OP_EDONKEYHEADER, OP_OUTOFPARTREQS) => {
                            info!("Peer session limit reached (OutOfPartReqs), will re-queue");
                            peer_out_of_parts = true;
                            break;
                        }
                        (OP_EMULEPROT, OP_QUEUEFULL) if payload.is_empty() => {
                            self.emit_source_detail_parts(event_tx, "queue_full", None, 0, 0, &client_software_label, &peer_name_label, src_avail_parts, src_total_parts).await;
                            anyhow::bail!("peer revoked upload slot (QueueFull during transfer)");
                        }
                        (OP_EMULEPROT, OP_QUEUERANKING) if payload.len() >= 2 => {
                            let rank = u16::from_le_bytes([payload[0], payload[1]]);
                            self.emit_source_detail_parts(event_tx, "queued", Some(rank as u32), 0, 0, &client_software_label, &peer_name_label, src_avail_parts, src_total_parts).await;
                            anyhow::bail!("peer put us back in queue at rank {} during transfer", rank);
                        }
                        (OP_EDONKEYHEADER, OP_QUEUERANK) if payload.len() >= 4 => {
                            let rank = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                            self.emit_source_detail_parts(event_tx, "queued", Some(rank), 0, 0, &client_software_label, &peer_name_label, src_avail_parts, src_total_parts).await;
                            anyhow::bail!("peer put us back in queue at rank {} during transfer", rank);
                        }
                        (OP_EDONKEYHEADER, OP_FILEREQANSNOFIL) => {
                            anyhow::bail!("peer no longer has the file (FileNotFound during transfer)");
                        }
                        (OP_EMULEPROT, OP_PUBLICKEY) if !payload.is_empty() => {
                            let key = if payload.len() >= 2 && payload[0] as usize == payload.len() - 1 {
                                payload[1..].to_vec()
                            } else {
                                payload.clone()
                            };
                            if let Some(cm) = &self.credit_manager {
                                let mut cm = cm.write().await;
                                cm.set_public_key(peer_user_hash, key);
                            }
                            if pending_secident_challenge.is_none() {
                                pending_secident_challenge = maybe_send_secident_challenge(
                                    &mut writer,
                                    self.credit_manager.as_ref(),
                                    peer_user_hash,
                                    self.source_addr,
                                    peer_secure_ident_level,
                                ).await?;
                            }
                        }
                        (OP_EMULEPROT, OP_SECIDENTSTATE) if payload.len() >= 5 => {
                            respond_to_secident_challenge(
                                &mut writer,
                                self.credit_manager.as_ref(),
                                payload[0],
                                u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]),
                                self.source_addr,
                                peer_user_hash,
                                peer_secure_ident_level,
                                0u32,
                            ).await?;
                        }
                        (OP_EMULEPROT, OP_SIGNATURE) if payload.len() >= 2 => {
                            handle_secident_signature(
                                self.credit_manager.as_ref(),
                                peer_user_hash,
                                &mut pending_secident_challenge,
                                self.source_addr,
                                peer_secure_ident_level,
                                &payload,
                                0u32,
                            ).await;
                        }
                        // eMule OP_FILEDESC: peer sends comment/rating for the file
                        (OP_EMULEPROT, OP_FILEDESC) if payload.len() >= 5 => {
                            let rating = payload[0];
                            let comment_len = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
                            if comment_len.checked_add(5).map_or(false, |need| payload.len() >= need) {
                                let comment = String::from_utf8_lossy(&payload[5..5+comment_len]).to_string();
                                if let Some(cm) = &self.comment_manager {
                                    let mut cm = cm.write().await;
                                    cm.add_peer_comment(
                                        &hex::encode(self.file_hash),
                                        self.source_addr.to_string(),
                                        rating,
                                        comment.clone(),
                                        0,
                                    );
                                }
                                debug!("Peer comment: rating={rating}, comment='{comment}'");
                            }
                        }
                        // AICH recovery answer from peer
                        (OP_EMULEPROT, OP_AICHANSWER) if payload.len() >= 38 => {
                            let mut ans_hash = [0u8; 16];
                            ans_hash.copy_from_slice(&payload[..16]);
                            let ans_part = u16::from_le_bytes([payload[16], payload[17]]) as usize;
                            let mut root_hash = [0u8; 20];
                            root_hash.copy_from_slice(&payload[18..38]);
                            let recovery_data = &payload[38..];
                            debug!(
                                "AICH answer: part={}, root={}, recovery={} bytes",
                                ans_part, hex::encode(root_hash), recovery_data.len()
                            );
                            if ans_hash == self.file_hash && ans_part == part_idx {
                                let master_ok = aich_master_hash.map_or(false, |m| m == root_hash);
                                if master_ok {
                                    aich_recovery_data = Some((root_hash, recovery_data.to_vec()));
                                } else {
                                    debug!(
                                        "Ignoring AICH answer: root {} != trusted master {:?}",
                                        hex::encode(root_hash),
                                        aich_master_hash.map(hex::encode)
                                    );
                                }
                            }
                        }
                        (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE) => {
                            if epx_packets_received >= crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION {
                                debug!("Ignoring excess EPX packet during download from {}", self.source_addr);
                            } else {
                                epx_packets_received += 1;
                                match crate::network::ember::parse_exchange_payload(&payload) {
                                    Ok(result) if !result.files.is_empty() || !result.peers.is_empty() => {
                                        info!("Received Ember Peer Exchange during download from {} ({} files, {} peers)", self.source_addr, result.files.len(), result.peers.len());
                                        let (epx_entries, aich_roots) = epx_result_to_entries(&result);
                                        let ember_peers = result.peers.into_iter().map(|p| (p.ip, p.tcp_port)).collect();
                                        let _ = event_tx
                                            .send(DownloadEvent::EmberSources {
                                                transfer_id: self.transfer_id.clone(),
                                                entries: epx_entries,
                                                aich_roots,
                                                ember_peers,
                                            })
                                            .await;
                                    }
                                    Ok(_) => {}
                                    Err(e) => debug!("Failed to parse Ember exchange: {e}"),
                                }
                            }
                        }
                        (OP_EMULEPROT, OP_EMBER_FRIEND_REQ) if peer_is_ember => {
                            if let Some(eh) = peer_ember_hash {
                                let nick = std::str::from_utf8(&payload).unwrap_or("").to_string();
                                let _ = event_tx.send(DownloadEvent::EmberFriendRequest {
                                    ember_hash: eh,
                                    nickname: nick,
                                    peer_ip: self.source_addr.ip().to_string(),
                                    peer_port: self.source_addr.port(),
                                }).await;
                            }
                        }
                        (OP_EMULEPROT, OP_EMBER_CHAT_MSG) if is_ember_friend && payload.len() <= 4096 => {
                            if let Some(eh) = peer_ember_hash {
                                if let Ok(msg) = std::str::from_utf8(&payload) {
                                    let _ = event_tx.send(DownloadEvent::EmberChatMessage {
                                        ember_hash: eh,
                                        message: msg.to_string(),
                                    }).await;
                                }
                            }
                        }
                        _ => {
                            debug!(
                                "During download, ignoring proto=0x{proto:02X} op=0x{opcode:02X}"
                            );
                        }
                    }

                    // When a request's worth of blocks is complete, send the next one
                    let blocks_in_current_batch = if completed_reqs < batches.len() {
                        batches[completed_reqs].len()
                    } else {
                        MAX_BLOCKS_PER_REQUEST
                    };
                    if blocks_received_in_current_req >= blocks_in_current_batch {
                        blocks_received_in_current_req = 0;
                        completed_reqs += 1;
                        // Pipeline refill: send next request if available
                        if sent_idx < batches.len() {
                            let batch = &batches[sent_idx];
                            let (req_payload, req_proto, req_op) = if needs_i64 {
                                (build_request_parts_i64(&self.file_hash, batch), OP_EMULEPROT, OP_REQUESTPARTS_I64)
                            } else {
                                (build_request_parts(&self.file_hash, batch), OP_EDONKEYHEADER, OP_REQUESTPARTS)
                            };
                            write_packet_async(
                                &mut writer,
                                req_proto,
                                req_op,
                                &req_payload,
                            )
                            .await?;
                            total_sent_bytes += batch.iter().map(|(s, e)| e - s).sum::<u64>();
                            sent_idx += 1;
                        }
                    }

                    // Update speed measurement every 2 seconds
                    let elapsed = speed_measure_start.elapsed();
                    if elapsed.as_millis() >= 2000 {
                        measured_speed = (speed_measure_bytes as u128 * 1000
                            / elapsed.as_millis().max(1)) as u64;
                        speed_measure_bytes = 0;
                        speed_measure_start = std::time::Instant::now();
                        self.emit_source_detail_parts(
                            event_tx, "transferring", None, measured_speed, downloaded,
                            &client_software_label, &peer_name_label, src_avail_parts, src_total_parts,
                        ).await;
                    }

                    if last_periodic_save.elapsed() >= PERIODIC_SAVE_INTERVAL {
                        tracker.save();
                        last_periodic_save = std::time::Instant::now();
                    }
                }

                if peer_out_of_parts {
                    continue;
                }

                // Guard against duplicate/overlapping blocks that satisfied the
                // byte budget without actually closing all gaps in this part.
                {
                    let (ps, pe) = tracker.part_range(part_idx);
                    let part_has_gaps = tracker.gap_list().iter().any(|&(gs, ge)| gs < pe && ge > ps);
                    if part_has_gaps {
                        warn!(
                            "Part {} byte budget met but gaps remain — peer likely sent duplicate blocks, marking for retry",
                            part_idx
                        );
                        tracker.save();
                        continue;
                    }
                }

                // Verify part hash if we have the hashset
                let part_verified = part_idx < part_hashes.len();
                if part_verified {
                    let expected_hash = part_hashes[part_idx];
                    let (ps, pe) = tracker.part_range(part_idx);
                    let part_len = (pe - ps) as usize;

                    let part_data = {
                        let out = output.clone();
                        tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
                            let mut f = out.lock().map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "file lock poisoned"))?;
                            f.seek(std::io::SeekFrom::Start(ps))?;
                            let mut buf = vec![0u8; part_len];
                            f.read_exact(&mut buf)?;
                            Ok(buf)
                        }).await.map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??
                    };

                    use digest::Digest;
                    use md4::Md4;
                    let actual_hash: [u8; 16] = Md4::digest(&part_data).into();

                    if actual_hash != expected_hash {
                        let aich_part = super::aich::compute_aich_part(&part_data);
                        let total_blocks = (part_data.len() + super::aich::AICH_BLOCK_SIZE - 1)
                            / super::aich::AICH_BLOCK_SIZE;
                        warn!(
                            "Part {} hash mismatch! expected={} got={}, part_aich={}, {} blocks in part",
                            part_idx,
                            hex::encode(expected_hash),
                            hex::encode(actual_hash),
                            hex::encode(aich_part),
                            total_blocks,
                        );

                        let mut recovery_bytes: Option<Vec<u8>> = aich_recovery_data
                            .as_ref()
                            .map(|(_, d)| d.clone());
                        if let Some(master_hash) = aich_master_hash {
                            if recovery_bytes.is_none() && peer_supports_aich {
                                let aich_should_try = if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                    if let Some(ref pending) = self.aich_pending {
                                        if let Ok(map) = pending.read() {
                                            match map.get(&(self.file_hash, part_idx as u32)) {
                                                Some((failed_ips, retry_count)) => {
                                                    !failed_ips.contains(&v4) && *retry_count < 3
                                                }
                                                None => true,
                                            }
                                        } else { true }
                                    } else { true }
                                } else { true };

                                if aich_should_try {
                                    let mut aich_req = Vec::with_capacity(38);
                                    aich_req.extend_from_slice(&self.file_hash);
                                    aich_req.extend_from_slice(&(part_idx as u16).to_le_bytes());
                                    aich_req.extend_from_slice(&master_hash);
                                    if let Err(e) =
                                        write_packet_async(&mut writer, OP_EMULEPROT, OP_AICHREQUEST, &aich_req).await
                                    {
                                        warn!("Failed to send OP_AICHREQUEST: {e}");
                                    } else {
                                        debug!("Sent OP_AICHREQUEST for part {part_idx}, waiting for answer");
                                        recovery_bytes = wait_for_aich_recovery_answer(
                                            &mut reader,
                                            &self.file_hash,
                                            part_idx,
                                            master_hash,
                                        )
                                        .await;
                                    }
                                } else {
                                    debug!("Skipping OP_AICHREQUEST for part {part_idx}: source already tried or retries exhausted");
                                }
                            }

                            let mut narrowed = false;
                            if let Some(ref rec) = recovery_bytes {
                                if let Some(corrupt) = super::aich::corrupt_blocks_from_aich_recovery(
                                    master_hash,
                                    rec,
                                    part_idx,
                                    &part_data,
                                    part_len,
                                    self.file_size,
                                ) {
                                    if !corrupt.is_empty() {
                                        let (ps, _) = tracker.part_range(part_idx);
                                        let mut invalidated = 0u64;
                                        for &bi in &corrupt {
                                            let rel = bi as u64 * super::aich::AICH_BLOCK_SIZE as u64;
                                            let gs = ps + rel;
                                            let ge = (gs + super::aich::AICH_BLOCK_SIZE as u64)
                                                .min(ps + part_len as u64);
                                            tracker.invalidate_range(gs, ge);
                                            invalidated += ge - gs;
                                        }
                                        tracker.save();
                                        downloaded = downloaded.saturating_sub(invalidated);
                                        let _ = event_tx
                                            .send(DownloadEvent::Progress {
                                                transfer_id: self.transfer_id.clone(),
                                                downloaded: downloaded.min(self.file_size),
                                                total: self.file_size,
                                            })
                                            .await;
                                        info!(
                                            "AICH narrowed part {} to {} bad 180KiB block(s), ~{} bytes to re-fetch",
                                            part_idx,
                                            corrupt.len(),
                                            invalidated
                                        );
                                        narrowed = true;
                                    }
                                }
                            }

                            if !narrowed {
                                if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                    let _ = event_tx
                                        .send(DownloadEvent::AichRecoveryFailed {
                                            file_hash: self.file_hash,
                                            part_index: part_idx as u32,
                                            failed_ip: v4,
                                        })
                                        .await;
                                }
                            }

                            if narrowed {
                                continue;
                            }
                        }

                        tracker.mark_incomplete(part_idx);
                        tracker.save();
                        downloaded = tracker.completed_bytes();
                        let _ = event_tx
                            .send(DownloadEvent::PartCorrupted {
                                file_hash: self.file_hash,
                                part_start: ps,
                                part_end: pe,
                            })
                            .await;
                        continue;
                    }
                    debug!("Part {} hash verified OK", part_idx);
                    let _ = event_tx
                        .send(DownloadEvent::PartVerified {
                            file_hash: self.file_hash,
                            part_start: ps,
                            part_end: pe,
                        })
                        .await;
                }

                if part_verified {
                    tracker.mark_complete(part_idx);
                }
                tracker.save();
            }

            // If peer ended the session, reset flag for next retry round
            peer_out_of_parts = false;
        }

        // Signal the uploader that we're done downloading from them
        write_packet_async(
            &mut writer,
            OP_EDONKEYHEADER,
            OP_END_OF_DOWNLOAD,
            &[],
        )
        .await
        .ok();

        self.emit_source_detail_parts(
            event_tx, "completed", None, measured_speed, downloaded.min(self.file_size), &client_software_label, &peer_name_label, src_avail_parts, src_total_parts,
        ).await;

        if !tracker.all_complete() {
            let remaining = tracker.part_count - tracker.completed_count();
            self.emit_source_failed(
                event_tx,
                &format!("{remaining} parts still failing hash verification"),
                downloaded.min(self.file_size),
                &client_software_label,
                &peer_name_label,
            ).await;
            anyhow::bail!(
                "{remaining} parts still failing hash verification after {max_part_rounds} retries"
            );
        }

        {
            let out = output.clone();
            tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                let f = out.lock().map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "file lock poisoned"))?;
                f.sync_data()?;
                Ok(())
            }).await.map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;
        }
        drop(output);

        let _ = event_tx
            .send(DownloadEvent::Verifying {
                transfer_id: self.transfer_id.clone(),
            })
            .await;

        // Verify the final file hash BEFORE moving the .part file.
        // Fast path: if all parts were individually hash-verified during download,
        // compute the file hash from the known part hashes (no disk I/O needed).
        // Fallback: re-read the entire file from disk if part hashes aren't available.
        let expected_hash = hex::encode(self.file_hash);
        let num_parts = ((self.file_size + super::hash::PARTSIZE - 1) / super::hash::PARTSIZE) as usize;
        let can_use_fast_verify = self.file_size >= super::hash::PARTSIZE
            && !part_hashes.is_empty()
            && part_hashes.len() >= num_parts;

        let verified_ok = if can_use_fast_verify {
            let actual_hash = super::hash::ed2k_hash_from_parts(&part_hashes, self.file_size);
            if actual_hash == expected_hash {
                info!("Download verified from part hashes (no re-read): {}", self.file_name);
                true
            } else {
                warn!(
                    "Download hash mismatch for {} (from parts): expected={}, got={} — falling back to full rehash",
                    self.file_name, expected_hash, actual_hash
                );
                let verify_path = part_path.clone();
                match tokio::task::spawn_blocking(move || {
                    super::hash::ed2k_hash_file(&verify_path)
                }).await {
                    Ok(Ok(h)) if h == expected_hash => { info!("Full rehash matched for {}", self.file_name); true }
                    Ok(Ok(h)) => { warn!("Full rehash also mismatched for {}: got={}", self.file_name, h); false }
                    Ok(Err(e)) => { warn!("Full rehash failed for {}: {e}", self.file_name); false }
                    Err(e) => { warn!("Full rehash task failed for {}: {e}", self.file_name); false }
                }
            }
        } else {
            let verify_path = part_path.clone();
            match tokio::task::spawn_blocking(move || {
                super::hash::ed2k_hash_file(&verify_path)
            }).await {
                Ok(Ok(actual_hash)) if actual_hash == expected_hash => {
                    info!("Download complete and verified: {}", self.file_name);
                    true
                }
                Ok(Ok(actual_hash)) => {
                    warn!(
                        "Download hash mismatch for {}: expected={}, got={}",
                        self.file_name, expected_hash, actual_hash
                    );
                    false
                }
                Ok(Err(e)) => {
                    warn!("Could not verify hash for {}: {e} — treating as failed", self.file_name);
                    false
                }
                Err(e) => {
                    warn!("Hash verification task failed for {}: {e} — treating as failed", self.file_name);
                    false
                }
            }
        };

        if !verified_ok {
            for i in 0..tracker.part_count {
                tracker.mark_incomplete(i);
            }
            tracker.save();
            warn!(
                "Final hash failed for {} — re-opened all {} parts for retry",
                self.file_name, tracker.part_count
            );
            anyhow::bail!(
                "Final hash verification failed — .part and .part.met preserved for retry"
            );
        }

        // Verification passed — safe to move file and clean up resume state
        {
            let pp = part_path.clone();
            let fp = final_path.clone();
            tokio::task::spawn_blocking(move || move_part_to_final(&pp, &fp))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;
        }
        tracker.delete_met();

        Ok(())
    }

    async fn acquire_download_bandwidth(&self, bytes: u64) {
        self.bandwidth_limiter.acquire_download(bytes).await;
    }
}

fn append_compressed_chunk(
    pending: &mut HashMap<u64, PendingCompressedBlock>,
    start: u64,
    total_packed_size: u32,
    chunk: &[u8],
) -> anyhow::Result<Option<Vec<u8>>> {
    let total_packed = total_packed_size as usize;
    if total_packed == 0 {
        anyhow::bail!("compressed part advertised zero packed size");
    }
    if total_packed > MAX_DECOMPRESSED_PART {
        anyhow::bail!("packed size {total_packed} exceeds limit");
    }
    let entry = pending.entry(start).or_insert_with(|| PendingCompressedBlock {
        compressed_total_size: total_packed_size,
        compressed: Vec::with_capacity(total_packed),
    });
    if entry.compressed_total_size != total_packed_size {
        let old_size = entry.compressed_total_size;
        let _ = entry;
        pending.remove(&start);
        anyhow::bail!(
            "compressed block at start={start}: size changed from {old_size} to {total_packed_size}",
        );
    }
    entry.compressed.extend_from_slice(chunk);
    let accumulated = entry.compressed.len();
    let max_compressed = total_packed + total_packed / 10 + 1024;
    if accumulated > max_compressed {
        pending.remove(&start);
        anyhow::bail!(
            "accumulated compressed data ({accumulated}) exceeds safety limit ({max_compressed}) for start={start}",
        );
    }
    if accumulated >= total_packed {
        let data = &entry.compressed;
        let decompressed = decompress_ed2k_part(data)?;
        pending.remove(&start);
        Ok(Some(decompressed))
    } else {
        Ok(None)
    }
}

/// eMule-style adaptive pipelining: number of OP_REQUESTPARTS packets to
/// keep in flight simultaneously based on observed connection speed.
/// Each request carries up to 3 blocks (EMBLOCKSIZE each).
/// Ref: eMule DownloadClient.cpp CreateBlockRequests() thresholds.
///
/// When `remaining_parts` <= 4 (near completion), eMule reduces to 1-2
/// blocks for slow connections to avoid wasting bandwidth on duplicate
/// requests that arrive after another source already finished the part.
///
/// `remaining_gap_bytes` tightens pipelining further in endgame (few bytes left).
/// Returns the max number of OP_REQUESTPARTS packets to keep in flight.
/// eMule counts individual blocks (each packet carries 3), so we compute
/// the block target and ceil-divide by 3 to get packet count.
fn outstanding_requests_for_speed_with_remaining(
    speed: u64,
    remaining_parts: usize,
    remaining_gap_bytes: u64,
) -> usize {
    // eMule block counts per speed tier (DownloadClient.cpp:804-810),
    // extended with higher tiers for modern broadband connections.
    // Safe because eMule upload side queues all incoming block requests.
    let mut blocks = if remaining_parts <= 4 {
        if speed < 600 {
            1
        } else if speed < 1200 {
            2
        } else if speed < 4 * 1024 {
            1
        } else if speed < 9 * 1024 {
            2
        } else if speed < 75 * 1024 {
            3
        } else if speed < 150 * 1024 {
            6
        } else {
            9
        }
    } else if speed < 4 * 1024 {
        1
    } else if speed < 9 * 1024 {
        2
    } else if speed < 75 * 1024 {
        3
    } else if speed < 150 * 1024 {
        6
    } else if speed < 300 * 1024 {
        9
    } else if speed < 1024 * 1024 {
        12
    } else {
        15
    };
    if remaining_parts <= 2 || remaining_gap_bytes <= PARTSIZE {
        blocks = blocks.min(3);
    } else if remaining_parts <= 4 || remaining_gap_bytes <= PARTSIZE.saturating_mul(3) {
        blocks = blocks.min(6);
    }
    // Convert block count to packet count (3 blocks per packet), min 1
    ((blocks + 2) / 3).max(1)
}

fn decompress_ed2k_part(compressed: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let zlib_result: anyhow::Result<Vec<u8>> = (|| {
        let mut decoder = ZlibDecoder::new(compressed);
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = decoder.read(&mut buf)?;
            if n == 0 { break; }
            out.extend_from_slice(&buf[..n]);
            if out.len() > MAX_DECOMPRESSED_PART {
                anyhow::bail!("decompressed part exceeds size limit");
            }
        }
        Ok(out)
    })();
    if let Ok(data) = zlib_result {
        return Ok(data);
    }
    let deflate_result: anyhow::Result<Vec<u8>> = (|| {
        let mut decoder = DeflateDecoder::new(compressed);
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = decoder.read(&mut buf)?;
            if n == 0 { break; }
            out.extend_from_slice(&buf[..n]);
            if out.len() > MAX_DECOMPRESSED_PART {
                anyhow::bail!("decompressed part exceeds size limit");
            }
        }
        Ok(out)
    })();
    if let Ok(data) = deflate_result {
        return Ok(data);
    }
    tracing::debug!(
        "decompress failed: len={}, first_bytes={:02X?}, zlib_err={}, deflate_err={}",
        compressed.len(),
        &compressed[..compressed.len().min(16)],
        zlib_result.as_ref().unwrap_err(),
        deflate_result.as_ref().unwrap_err(),
    );
    Err(zlib_result.unwrap_err())
}

/// Writes an empty `.part`, verifies ed2k hash ([`super::hash::empty_ed2k_file_md4`]), moves to Downloads.
pub(super) async fn finalize_zero_ed2k_file(
    transfer_id: &str,
    file_name: &str,
    file_hash: [u8; 16],
    download_dir: &std::path::Path,
) -> anyhow::Result<()> {
    if file_hash != super::hash::empty_ed2k_file_md4() {
        anyhow::bail!(
            "zero-byte ed2k file requires file hash {}",
            hex::encode(super::hash::empty_ed2k_file_md4())
        );
    }
    let temp_dir = download_dir.join("Temp");
    let completed_dir = download_dir.join("Downloads");
    tokio::fs::create_dir_all(&temp_dir).await?;
    tokio::fs::create_dir_all(&completed_dir).await?;
    let safe_name = crate::security::sanitize_filename(file_name);
    let part_path = temp_dir.join(format!("{transfer_id}.part"));
    let final_path = completed_dir.join(&safe_name);
    let _ = tokio::fs::remove_file(&part_path).await;
    let _ = tokio::fs::remove_file(part_path.with_extension("part.met")).await;
    tokio::fs::write(&part_path, []).await?;
    let verify_path = part_path.clone();
    let expected = hex::encode(file_hash);
    let ok = tokio::task::spawn_blocking(move || {
        super::hash::ed2k_hash_file(&verify_path).map(|h| h == expected)
    })
    .await
    .map_err(|e| anyhow::anyhow!("hash task: {e}"))??;
    if !ok {
        anyhow::bail!("zero-byte file ed2k hash verification failed");
    }
    let pp = part_path.clone();
    let fp = final_path.clone();
    tokio::task::spawn_blocking(move || move_part_to_final(&pp, &fp))
        .await
        .map_err(|e| anyhow::anyhow!("rename task: {e}"))??;
    Ok(())
}

fn is_cross_device_error(e: &std::io::Error) -> bool {
    #[cfg(windows)]
    { matches!(e.raw_os_error(), Some(17)) } // ERROR_NOT_SAME_DEVICE
    #[cfg(not(windows))]
    { matches!(e.raw_os_error(), Some(18)) } // EXDEV
}

/// eMule-style filename deduplication: if `base` already exists, try
/// `stem (1).ext`, `stem (2).ext`, … up to 9999 before giving up.
pub(crate) fn dedup_path(base: &std::path::Path) -> std::path::PathBuf {
    if !base.exists() {
        return base.to_path_buf();
    }
    let stem = base.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = base.extension().and_then(|s| s.to_str());
    let parent = base.parent().unwrap_or(base);
    for i in 1..=9999u32 {
        let candidate = if let Some(ext) = ext {
            parent.join(format!("{stem} ({i}).{ext}"))
        } else {
            parent.join(format!("{stem} ({i})"))
        };
        if !candidate.exists() {
            return candidate;
        }
    }
    let fallback = if let Some(ext) = ext {
        parent.join(format!("{stem} (10000).{ext}"))
    } else {
        parent.join(format!("{stem} (10000)"))
    };
    fallback
}

/// Move (or copy+delete) a `.part` file to its final destination, deduplicating
/// the filename if the target already exists.  Returns the actual final path.
pub(crate) fn move_part_to_final(
    part_path: &std::path::Path,
    target: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
    let final_path = dedup_path(target);
    if let Err(e) = std::fs::rename(part_path, &final_path) {
        if is_cross_device_error(&e) {
            std::fs::copy(part_path, &final_path)?;
            std::fs::remove_file(part_path).map_err(|rm_err| {
                tracing::warn!(
                    "Failed to remove .part after cross-device copy: {}",
                    rm_err
                );
                rm_err
            })?;
        } else {
            return Err(e.into());
        }
    }
    Ok(final_path)
}

/// Verify that peer-supplied part MD4s combine to the ed2k file hash (eMule `CFileIdentifier` / hashset handling).
///
/// The on-wire hashset is **one MD4 per full or partial part** (same chunking as [`super::hash::ed2k_hash_file`](super::hash::ed2k_hash_file)).
/// It does **not** include the trailing `MD4("")` block; when `file_size > 0` and `file_size % PARTSIZE == 0`,
/// that sentinel is appended here before the final MD4, matching eMule and our `ed2k_hash_file` rules.
///
/// Special case: `file_size < PARTSIZE` with a single hash — the file hash is `MD4(data)` (not `MD4(MD4(data)‖…)`),
/// so we compare the lone part hash to the file hash directly.
pub(super) fn verify_hashset(file_hash: &[u8; 16], part_hashes: &[[u8; 16]], file_size: u64) -> bool {
    use md4::{Digest, Md4};
    if part_hashes.is_empty() {
        return false;
    }
    if part_hashes.len() == 1 && file_size < super::hash::PARTSIZE {
        return part_hashes[0] == *file_hash;
    }
    let mut combined = Vec::with_capacity((part_hashes.len() + 1) * 16);
    for h in part_hashes {
        combined.extend_from_slice(h);
    }
    if file_size > 0 && file_size % super::hash::PARTSIZE == 0 {
        let empty_hash: [u8; 16] = Md4::digest([]).into();
        combined.extend_from_slice(&empty_hash);
    }
    let computed: [u8; 16] = Md4::digest(&combined).into();
    computed == *file_hash
}

fn parse_sending_part_32(payload: &[u8]) -> std::io::Result<([u8; 16], u64, u64, &[u8])> {
    if payload.len() < 24 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sending part 32 too short",
        ));
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let start = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]) as u64;
    let end = u32::from_le_bytes([payload[20], payload[21], payload[22], payload[23]]) as u64;
    Ok((hash, start, end, &payload[24..]))
}

pub(crate) async fn maybe_send_secident_challenge<W: AsyncWriteExt + Unpin + ?Sized>(
    writer: &mut W,
    credit_manager: Option<&Arc<tokio::sync::RwLock<CreditManager>>>,
    peer_user_hash: [u8; 16],
    peer_addr: SocketAddr,
    peer_secident_level: u8,
) -> std::io::Result<Option<u32>> {
    let Some(cm) = credit_manager else {
        return Ok(None);
    };
    let peer_ip_u32 = match peer_addr.ip() {
        std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v4| u32::from_be_bytes(v4.octets())).unwrap_or(0),
    };
    let cm = cm.read().await;
    let Some(state) = cm.secident_request_state(&peer_user_hash, peer_ip_u32, peer_secident_level) else {
        return Ok(None);
    };
    let challenge = rand::random::<u32>().wrapping_add(1);
    let mut secident_payload = Vec::with_capacity(5);
    secident_payload.push(state);
    secident_payload.extend_from_slice(&challenge.to_le_bytes());
    write_packet_async(writer, OP_EMULEPROT, OP_SECIDENTSTATE, &secident_payload).await?;
    Ok(Some(challenge))
}

pub(crate) async fn respond_to_secident_challenge<W: AsyncWriteExt + Unpin + ?Sized>(
    writer: &mut W,
    credit_manager: Option<&Arc<tokio::sync::RwLock<CreditManager>>>,
    state: u8,
    challenge: u32,
    peer_addr: SocketAddr,
    peer_user_hash: [u8; 16],
    peer_secident_level: u8,
    our_client_id: u32,
) -> std::io::Result<()> {
    let Some(cm) = credit_manager else {
        return Ok(());
    };
    let peer_ip_u32 = match peer_addr.ip() {
        std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v4| u32::from_be_bytes(v4.octets())).unwrap_or(0),
    };
    let cm = cm.read().await;
    if state >= 2 {
        let pub_key = cm.our_public_key().to_vec();
        if !pub_key.is_empty() {
            let mut key_pkt = Vec::with_capacity(1 + pub_key.len());
            key_pkt.push(pub_key.len() as u8);
            key_pkt.extend_from_slice(&pub_key);
            write_packet_async(writer, OP_EMULEPROT, OP_PUBLICKEY, &key_pkt).await?;
        }
    }
    let (challenge_ip_kind, challenge_ip, add_trailer) = if (peer_secident_level & 1) != 0 {
        (None, 0u32, false)
    } else {
        // eMule: use REMOTECLIENT if we don't know our own public IP (LowID)
        if our_client_id == 0 || our_client_id < 0x0100_0000 {
            (Some(super::credits::CRYPT_CIP_REMOTECLIENT), peer_ip_u32, true)
        } else {
            (Some(super::credits::CRYPT_CIP_LOCALCLIENT), our_client_id, true)
        }
    };
    let sig = cm.create_signature_for_peer(&peer_user_hash, challenge, challenge_ip, challenge_ip_kind);
    if !sig.is_empty() {
        let mut sig_pkt = Vec::with_capacity(2 + sig.len() + usize::from(add_trailer));
        sig_pkt.push(sig.len() as u8);
        sig_pkt.extend_from_slice(&sig);
        if add_trailer {
            sig_pkt.push(challenge_ip_kind.unwrap_or(super::credits::CRYPT_CIP_NONECLIENT));
        }
        write_packet_async(writer, OP_EMULEPROT, OP_SIGNATURE, &sig_pkt).await?;
    }
    Ok(())
}

pub(crate) async fn handle_secident_signature(
    credit_manager: Option<&Arc<tokio::sync::RwLock<CreditManager>>>,
    peer_user_hash: [u8; 16],
    pending_secident_challenge: &mut Option<u32>,
    peer_addr: SocketAddr,
    peer_secident_level: u8,
    payload: &[u8],
    our_client_id: u32,
) {
    let Some(cm) = credit_manager else {
        return;
    };
    let sig_len = payload[0] as usize;
    if sig_len == 0 || payload.len() < 1 + sig_len {
        return;
    }
    let Some(challenge) = pending_secident_challenge.take() else {
        return;
    };
    let peer_ip_u32 = match peer_addr.ip() {
        std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v4| u32::from_be_bytes(v4.octets())).unwrap_or(0),
    };
    let sig_bytes = &payload[1..1 + sig_len];
    let challenge_kind = if payload.len() == 1 + sig_len {
        None
    } else if payload.len() == 2 + sig_len && (peer_secident_level & 2) != 0 {
        Some(payload[1 + sig_len])
    } else {
        return;
    };
    let verified = {
        let cm = cm.read().await;
        let local_ip = if our_client_id >= 0x0100_0000 { our_client_id } else { 0 };
        cm.verify_signature(&peer_user_hash, challenge, challenge_kind, peer_ip_u32, local_ip, sig_bytes)
    };
    let mut cm = cm.write().await;
    if verified {
        cm.set_ident_state(peer_user_hash, IdentState::Verified);
        cm.check_identity_ip(peer_user_hash, peer_ip_u32);
    } else {
        cm.set_ident_state(peer_user_hash, IdentState::Failed);
    }
}

/// Wait for `OP_AICHANSWER` matching file, part, and trusted AICH master hash (up to ~8s).
async fn wait_for_aich_recovery_answer<R: AsyncReadExt + Unpin + ?Sized>(
    reader: &mut R,
    file_hash: &[u8; 16],
    part_idx: usize,
    expected_master: [u8; 20],
) -> Option<Vec<u8>> {
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(8);
    let deadline = tokio::time::Instant::now() + MAX_WAIT;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let chunk = remaining.min(std::time::Duration::from_secs(2));
        match tokio::time::timeout(chunk, read_packet_async(reader)).await {
            Ok(Ok((proto, opcode, payload))) => {
                if proto == OP_EMULEPROT && opcode == OP_AICHANSWER && payload.len() >= 38 {
                    let mut ans_hash = [0u8; 16];
                    ans_hash.copy_from_slice(&payload[..16]);
                    let ans_part = u16::from_le_bytes([payload[16], payload[17]]) as usize;
                    let mut root = [0u8; 20];
                    root.copy_from_slice(&payload[18..38]);
                    if ans_hash == *file_hash && ans_part == part_idx && root == expected_master {
                        return Some(payload[38..].to_vec());
                    }
                }
            }
            Ok(Err(_)) => return None,
            Err(_) => {}
        }
    }
    None
}

async fn read_packet_with_timeout<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    tokio::time::timeout(
        std::time::Duration::from_secs(READ_TIMEOUT_SECS),
        read_packet_async(reader),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timed out"))?
}

async fn read_packet_async<R: AsyncReadExt + Unpin + ?Sized>(
    reader: &mut R,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    const OP_PACKEDPROT: u8 = 0xD4;
    let protocol = reader.read_u8().await?;
    let length = reader.read_u32_le().await? as usize;
    if length == 0 || length > 10 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid packet length",
        ));
    }
    let opcode = reader.read_u8().await?;
    let payload_len = length - 1;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    if protocol == OP_PACKEDPROT {
        let mut decoder = ZlibDecoder::new(&payload[..]);
        let mut unpacked = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = decoder.read(&mut buf)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("packed decode failed: {e}")))?;
            if n == 0 { break; }
            unpacked.extend_from_slice(&buf[..n]);
            if unpacked.len() > 10 * 1024 * 1024 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "packed packet decompressed size exceeds limit"));
            }
        }
        return Ok((OP_EMULEPROT, opcode, unpacked));
    }
    Ok((protocol, opcode, payload))
}

async fn write_packet_async<W: AsyncWriteExt + Unpin + ?Sized>(
    writer: &mut W,
    protocol: u8,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    writer.write_u8(protocol).await?;
    let pkt_len = u32::try_from(1 + payload.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "packet payload too large"))?;
    writer.write_u32_le(pkt_len).await?;
    writer.write_u8(opcode).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}
