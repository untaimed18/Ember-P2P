use std::collections::HashMap;
use std::io::Read;
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

use super::comments::CommentManager;
use super::credits::{CreditManager, IdentState};
use super::messages::*;
use super::part_tracker::PartTracker;
use super::sources::SourceManager;

const READ_TIMEOUT_SECS: u64 = super::dead_sources::DOWNLOADTIMEOUT_SECS as u64;

/// Maximum decompressed part size (PARTSIZE + margin = 10 MiB)
const MAX_DECOMPRESSED_PART: usize = 10 * 1024 * 1024;

/// Returns `true` if the IP should be rejected as a source exchange result.
///
/// Delegates to `security::is_special_use_v4` so every parser path that
/// accepts IPs from the wire (OP_ANSWERSOURCES, SX, EPX injection) uses the
/// same predicate — RFC-1918, loopback, link-local, broadcast, CGNAT (RFC
/// 6598 100.64/10), documentation (TEST-NET-1/2/3), and benchmarking
/// (198.18/15) ranges.
pub(super) fn is_filtered_source_ip(ip: &std::net::Ipv4Addr) -> bool {
    crate::security::is_special_use_v4(*ip)
}

/// Convert parsed EPX result into the flattened vectors used by DownloadEvent.
pub(crate) fn epx_result_to_entries(
    result: &crate::network::ember::ExchangeResult,
) -> (
    Vec<([u8; 16], Vec<(std::net::Ipv4Addr, u16, u16, u8)>)>,
    Vec<([u8; 16], [u8; 20])>,
) {
    let entries = result
        .files
        .iter()
        .map(|e| {
            let srcs = e
                .sources
                .iter()
                .map(|s| (s.ip, s.tcp_port, s.udp_port, s.flags))
                .collect();
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
    /// Our Ed25519 public key, advertised in `OP_EMBER_HELLO` /
    /// `OP_EMBER_HELLOANSWER` so the peer can run the
    /// `verify_ember_hash_binding` check against us. Used on the
    /// single-source download path to advertise an Ember-verifiable
    /// identity symmetrically with the multi-source path — so an
    /// `EmberFriendRequest` emitted from this code reports an honest
    /// `verified=true` whenever the peer's own pubkey + hash bind
    /// correctly (mirrors `multi_source.rs`'s binding-only check; the
    /// full `perform_ember_auth` proof-of-possession still runs on
    /// friend-connect dial-back).
    pub ed25519_public_key: [u8; 32],
    /// Our Ed25519 secret key. Held on the struct so any future
    /// patch that introduces the packet-buffering
    /// `perform_ember_auth` wrapper on the download side can sign
    /// peer challenges without another plumbing pass.
    pub ed25519_secret_key: [u8; 32],
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
    /// Lock-free counter that the per-source loop bumps on every
    /// peer-to-peer Source Exchange packet (`OP_REQUESTSOURCES`,
    /// `OP_ANSWERSOURCES`, and `OP_EMBER_SOURCEEXCHANGE`) it sends
    /// or receives. Drained on the network loop's stats tick into
    /// `OverheadCategory::SourceExchange` so the Statistics page
    /// reflects real peer-SX traffic, not just server source-asking.
    pub sx_overhead: crate::storage::statistics::SharedSxOverheadCounters,
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
        /// Absolute path the finished file was actually written to. May
        /// differ from `Downloads/<name>` when `move_part_to_final`
        /// deduplicated against a pre-existing file. `None` for completion
        /// paths that don't move a `.part` (e.g. zero-byte files) — the
        /// handler then falls back to reconstructing the path.
        final_path: Option<String>,
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
        relay_attestations: Vec<crate::network::ember::RelayAttestation>,
    },
    /// An Ember peer was detected (for peer discovery mesh bootstrap).
    EmberPeerDiscovered {
        ip: std::net::Ipv4Addr,
        tcp_port: u16,
    },
    /// Incoming friend request from an Ember peer.
    ///
    /// `verified` reflects the strongest identity claim that could be
    /// established by the time the request was emitted:
    ///   - `true` iff the peer advertised an Ed25519 public key whose
    ///     BLAKE3 prefix matches their advertised `ember_hash` (the
    ///     cheap offline identity-binding check in
    ///     `crate::network::ember::crypto::verify_ember_hash_binding`).
    ///     On paths that run `friend_connect::perform_ember_auth` this
    ///     additionally implies signature-based proof of possession.
    ///   - `false` when no public key was advertised, or the key was
    ///     present but the binding check failed (mismatches are dropped
    ///     before reaching this event in the emit paths).
    EmberFriendRequest {
        ember_hash: [u8; 16],
        nickname: String,
        peer_ip: String,
        peer_port: u16,
        verified: bool,
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
        #[allow(dead_code)]
        sender_user_hash: Option<[u8; 16]>,
    },
    /// A part passed its MD4 hash check.
    PartVerified {
        file_hash: [u8; 16],
        part_start: u64,
        part_end: u64,
        sender_user_hash: Option<[u8; 16]>,
    },
    /// A part failed its MD4 hash check.
    PartCorrupted {
        file_hash: [u8; 16],
        part_start: u64,
        part_end: u64,
        sender_user_hash: Option<[u8; 16]>,
    },
    /// AICH recovery was attempted for a corrupt part but failed (timeout, bad data, etc.).
    /// The network loop uses this to schedule a retry with a different source.
    AichRecoveryFailed {
        file_hash: [u8; 16],
        part_index: u32,
        failed_ip: std::net::Ipv4Addr,
    },
    /// A peer broke the ed2k wire protocol badly enough that we tore the
    /// connection down — currently a run of consecutive structurally
    /// invalid data blocks (bad offsets / over-long compressed chunks),
    /// which a well-behaved client never sends. The network loop feeds
    /// this into the reputation tracker as a `ProtocolViolation`, so a
    /// peer that repeatedly does this is eventually banned rather than
    /// just disconnected and immediately retried.
    ProtocolViolation {
        sender_ip: std::net::Ipv4Addr,
        sender_user_hash: Option<[u8; 16]>,
    },
}

/// Shared pending AICH recovery retries: `(file_hash, part_index) -> (failed_ips, retry_count)`.
/// Written by the network event loop, read by download tasks before sending OP_AICHREQUEST.
pub type SharedAichPending = std::sync::Arc<
    std::sync::RwLock<std::collections::HashMap<([u8; 16], u32), (Vec<std::net::Ipv4Addr>, u32)>>,
>;

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
    } else if lower.contains("download timeout") || lower.contains("more than 100 seconds") {
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

/// True when a per-source download task unwound because the user
/// Stopped/Cancelled/Paused the transfer (the strings produced by the
/// `TransferControl` cancel/pause arms and `check_control`), rather than
/// because the source genuinely failed. Such unwinds must NOT emit a
/// `SourceDetail{status:"failed"}` event, because that applies a reputation
/// penalty (`set_failed_with_penalty`) — and `PauseDownload` keeps the
/// per-file source list for fast resume, so repeated pause/resume cycles
/// would otherwise steadily degrade and eventually evict a transfer's best
/// peers. eMule treats a user pause/stop as a clean teardown.
pub(crate) fn is_user_cancel_error(error: &str) -> bool {
    error.contains("cancelled by user") || error.contains("cancelled while paused")
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
        assert_eq!(
            summarize_error("stage:data_wait download timeout: no data for 100s", &kind),
            "Download timed out"
        );
        assert_eq!(failure_kind_name(&kind), "download_timeout");
    }

    #[test]
    fn summarize_missing_file_error_is_user_friendly() {
        let kind = classify_error("peer does not have the file");
        assert_eq!(kind, SourceFailureKind::Permanent);
        assert_eq!(
            summarize_error("peer does not have the file", &kind),
            "Remote missing file"
        );
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
            // Recover the guard if the lock is poisoned (a writer panicked)
            // instead of skipping the check — silently bypassing the IP filter
            // would let a banned/filtered peer through (fail-open security hole).
            let snap = filter.read().unwrap_or_else(|e| e.into_inner());
            if snap.is_blocked(*ip) {
                return true;
            }
        }
        if let Some(ref banned) = self.banned_ips {
            let set = banned.read().unwrap_or_else(|e| e.into_inner());
            if set.contains(ip) {
                return true;
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
    async fn complete_zero_byte_local(
        &self,
        event_tx: &mpsc::Sender<DownloadEvent>,
    ) -> anyhow::Result<std::path::PathBuf> {
        self.emit_source_detail(event_tx, "connecting", None, 0, 0, "", "")
            .await;
        let _ = event_tx
            .send(DownloadEvent::Verifying {
                transfer_id: self.transfer_id.clone(),
            })
            .await;
        let final_path = finalize_zero_ed2k_file(
            &self.transfer_id,
            &self.file_name,
            self.file_hash,
            &self.download_dir,
        )
        .await?;
        self.emit_source_detail(event_tx, "completed", None, 0, 0, "", "")
            .await;
        let _ = event_tx
            .send(DownloadEvent::Progress {
                transfer_id: self.transfer_id.clone(),
                downloaded: 0,
                total: 0,
            })
            .await;
        Ok(final_path)
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
        self.emit_source_detail_parts(
            event_tx,
            status,
            queue_rank,
            speed,
            transferred,
            client_software,
            peer_name,
            None,
            None,
        )
        .await;
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
            hex::encode(self.file_hash),
            self.source_addr
        );

        if self.file_size == 0 {
            let zero_final = self.complete_zero_byte_local(&event_tx).await?;
            let _ = event_tx
                .send(DownloadEvent::Completed {
                    transfer_id: self.transfer_id.clone(),
                    final_path: Some(zero_final.to_string_lossy().into_owned()),
                })
                .await;
            return Ok(());
        }

        self.emit_source_detail(&event_tx, "connected (callback)", None, 0, 0, "", "")
            .await;

        if let Some(sm) = &self.source_manager {
            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                let mut sm = sm.write().await;
                sm.register_source(self.file_hash, v4, self.source_addr.port());
            }
        }

        let mut completed_path_out: Option<String> = None;
        match self
            .download_from_streams(
                &mut *reader,
                &mut *writer,
                peer_user_hash,
                PeerCapabilities::default(),
                &event_tx,
                emule_info_done,
                &mut completed_path_out,
            )
            .await
        {
            Ok(_) => {
                let _ = event_tx
                    .send(DownloadEvent::Completed {
                        transfer_id: self.transfer_id.clone(),
                        final_path: completed_path_out,
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
        // Set to the real on-disk destination once the `.part` is moved to
        // its final location, so the caller's `Completed` event can carry
        // the deduplicated path instead of letting Open/Reveal reconstruct
        // (and mis-resolve) it from the file name.
        completed_path_out: &mut Option<String>,
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
        // Ember-hello-derived state. Mirrors the `multi_source.rs`
        // binding-verification flow: we learn the peer's Ed25519
        // public key from `OP_EMBER_HELLO` / `OP_EMBER_HELLOANSWER`,
        // run the offline `verify_ember_hash_binding` check (BLAKE3
        // prefix vs. advertised ember_hash), and thread the result
        // through to every `DownloadEvent::EmberFriendRequest` this
        // session emits so the Friends UI can render a trustworthy
        // verification badge on single-source downloads — previously
        // those always landed with `verified=false` regardless of
        // whether the peer carried a valid identity claim.
        let mut peer_ember_pubkey: Option<[u8; 32]> = None;
        let mut ember_hash_binding_verified = false;
        // Strict proof-of-possession flag. Mirrors the `multi_source.rs`
        // contract: `true` iff `perform_ember_auth_buffered` completed
        // successfully on THIS TCP session — the peer signed a fresh
        // random nonce we issued with the matching Ed25519 secret key.
        // Implies `ember_hash_binding_verified`. Used to mark
        // `EmberFriendRequest.verified` as PoP-backed rather than
        // binding-only, and to gate privilege-bearing friend opcodes
        // (CHAT_MSG) on genuine identity ownership.
        let mut ember_auth_verified = false;
        // Whether we've already promoted this session's PoP success
        // to a `DownloadEvent::FriendSeen`. We only emit once per
        // session so the dispatcher doesn't get repeated address-
        // update events for the same peer.
        let mut friend_seen_emitted = false;
        // FIFO of non-AUTH packets captured by
        // `perform_ember_auth_buffered` while it waited for CHALLENGE /
        // RESPONSE. The uploader emits proactive
        // `OP_SECIDENTSTATE` / `OP_PUBLICKEY` / `OP_SIGNATURE` / EPX
        // frames immediately after its `OP_EMBER_HELLO`; those queue
        // ahead of the uploader's auth response and would be silently
        // dropped by the non-buffered `perform_ember_auth`. We capture
        // them here and the pre-control / file-status-wait loop heads
        // below drain this deque before reading fresh packets from the
        // stream, so the main dispatch arms still see them in arrival
        // order and SecIdent credit accounting stays correct.
        let mut auth_deferred: std::collections::VecDeque<(u8, u8, Vec<u8>)> =
            std::collections::VecDeque::new();
        let mut sent_ember_hello = false;
        let mut epx_packets_received: u8 = 0;
        let mut early_upload_accept = false;
        let mut pending_secident_challenge: Option<u32> = None;
        let mut pending_peer_challenge: Option<(u32, u8)> = None;

        let mut deferred_packet: Option<(u8, u8, Vec<u8>)> = None;
        let mut client_software_label = client_software_from_caps(&initial_caps);
        let mut peer_name_label = initial_caps.peer_name.clone();
        let our_client_id = self
            .external_ip
            .map(|ip| u32::from_le_bytes(ip.octets()))
            .unwrap_or(0);

        let peer_is_new_emule =
            initial_caps.emule_version_min > 0 || initial_caps.version_major > 0;
        // `did_proactive_challenge` tracks whether `maybe_send_secident_challenge`
        // fired inside the branches below (it does, for the classic pre-EmuleInfo
        // peer path). After the match we send it unconditionally if we haven't
        // already — so the modern-eMule "fast path" (where the peer's Hello
        // carries CT_EMULE_VERSION and they short-circuit the EmuleInfo
        // exchange entirely, sending OP_SECIDENTSTATE directly after their
        // HelloAnswer — see BaseClient.cpp:659-664 / ListenSocket.cpp:284)
        // still gets its SecIdent kick-off. Without this, eMule treats us as
        // `IS_NOTAVAILABLE` on the download side and our peer sees us the
        // same way, which is exactly the symptom we just fixed on uploads.
        let mut did_proactive_challenge = false;
        if skip_emule_info || peer_is_new_emule {
            debug!(
                "Skipping EmuleInfo exchange (already done via obfuscation or Hello eMule tags)"
            );
        } else {
            let emule_payload = build_emule_info(
                self.udp_port,
                self.obfuscation_enabled,
                Some(&self.ember_hash),
                None,
            );
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
                    peer_caps.compression_ver,
                    peer_caps.supports_large_files,
                    peer_caps.source_exchange_ver,
                    peer_caps.supports_source_ex2,
                    peer_caps.kad_version,
                    peer_caps.kad_port,
                    peer_caps.supports_crypt_layer,
                    peer_caps.requests_crypt_layer,
                    peer_caps.requires_crypt_layer,
                    peer_caps.supports_multi_packet,
                    peer_caps.ext_multi_packet,
                    peer_caps.supports_aich,
                    peer_caps.supports_unicode,
                    peer_caps.supports_secure_ident,
                    peer_caps.supports_preview,
                    peer_caps.supports_captcha,
                    peer_caps.supports_file_ident,
                    peer_caps.supports_direct_udp_callback,
                    peer_caps.compatible_client,
                    peer_caps.emule_version_min,
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
                            sm.register_source_full(
                                self.file_hash,
                                v4,
                                self.source_addr.port(),
                                peer_udp,
                                peer_user_hash,
                            );
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
                )
                .await?;
                did_proactive_challenge = true;
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
                            sm.register_source_full(
                                self.file_hash,
                                v4,
                                self.source_addr.port(),
                                peer_udp,
                                peer_user_hash,
                            );
                        }
                    }
                }
                let emule_answer = build_emule_info(
                    self.udp_port,
                    self.obfuscation_enabled,
                    Some(&self.ember_hash),
                    None,
                );
                write_packet_async(&mut writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &emule_answer)
                    .await?;
                debug!("Received peer OP_EMULEINFO, replied with OP_EMULEINFOANSWER");
                pending_secident_challenge = maybe_send_secident_challenge(
                    &mut writer,
                    self.credit_manager.as_ref(),
                    peer_user_hash,
                    self.source_addr,
                    peer_secure_ident_level,
                )
                .await?;
                did_proactive_challenge = true;
            } else {
                debug!("Peer skipped EmuleInfoAnswer (got proto=0x{proto2:02X} op=0x{opcode2:02X}), deferring");
                deferred_packet = Some((proto2, opcode2, payload2));
            }
        }

        // Fire the SecIdent kick-off if the branches above didn't already.
        // Covers (a) `skip_emule_info || peer_is_new_emule` — the modern
        // eMule fast path that never sends OP_EMULEINFO, and
        // (b) the `else { deferred_packet }` branch where the peer sent an
        // unrelated packet (often OP_SECIDENTSTATE itself). In both cases
        // the peer is waiting for our OP_SECIDENTSTATE before it will ship
        // its own OP_PUBLICKEY / OP_SIGNATURE, so without this call the
        // handshake deadlocks and both sides settle at IS_NOTAVAILABLE.
        // `maybe_send_secident_challenge` is a no-op when the peer doesn't
        // advertise SecIdent or we have no local keypair.
        if !did_proactive_challenge {
            pending_secident_challenge = maybe_send_secident_challenge(
                &mut writer,
                self.credit_manager.as_ref(),
                peer_user_hash,
                self.source_addr,
                peer_secure_ident_level,
            )
            .await?;
        }

        // Handle secure identification packets that may arrive before file requests.
        // Be passive: store peer key material and answer explicit challenges.
        //
        // Iteration count bumped from 3 → 12 to mirror `multi_source.rs`:
        // `perform_ember_auth_buffered` (invoked from the OP_EMBER_HELLO
        // handler below) can capture up to AUTH_PACKET_MAX_SKIPS (8)
        // non-AUTH packets while waiting for the peer's CHALLENGE /
        // RESPONSE. Those captured packets are drained from
        // `auth_deferred` at the top of this loop on subsequent
        // iterations, and we need enough rounds to actually replay
        // them through the SecIdent / EPX match arms before
        // file-status-wait kicks in.
        for _ in 0..12 {
            let (p, o, pl) = if let Some(pkt) = deferred_packet.take() {
                pkt
            } else if let Some(pkt) = auth_deferred.pop_front() {
                // Replay a packet that `perform_ember_auth_buffered`
                // captured while waiting for an AUTH opcode — process
                // it through the standard match arms below so
                // SecIdent credit accounting still works for
                // Ember-to-Ember single-source downloads.
                pkt
            } else {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    read_packet_async(&mut reader),
                )
                .await
                {
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
                            our_client_id,
                        )
                        .await?;
                    }
                    if pending_secident_challenge.is_none() {
                        pending_secident_challenge = maybe_send_secident_challenge(
                            &mut writer,
                            self.credit_manager.as_ref(),
                            peer_user_hash,
                            self.source_addr,
                            peer_secure_ident_level,
                        )
                        .await?;
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
                            our_client_id,
                        )
                        .await?;
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
                        our_client_id,
                    )
                    .await;
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
                                sm.register_source_full(
                                    self.file_hash,
                                    v4,
                                    self.source_addr.port(),
                                    peer_udp,
                                    peer_user_hash,
                                );
                            }
                        }
                    }
                    if o == OP_EMULEINFO {
                        let emule_answer = build_emule_info(
                            self.udp_port,
                            self.obfuscation_enabled,
                            Some(&self.ember_hash),
                            None,
                        );
                        let _ = write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_EMULEINFOANSWER,
                            &emule_answer,
                        )
                        .await;
                        debug!(
                            "Received delayed peer OP_EMULEINFO, replied with OP_EMULEINFOANSWER"
                        );
                    } else {
                        debug!("Got delayed EmuleInfoAnswer");
                    }
                }
                (OP_EDONKEYHEADER, OP_ACCEPTUPLOADREQ) => {
                    early_upload_accept = true;
                    debug!("Received early AcceptUploadReq before file status");
                }
                // EPX is an Ember-only extension; gate reception on
                // `peer_is_ember` exactly as the upload side does
                // (`upload.rs` OP_EMBER_SOURCEEXCHANGE arm). Without this a
                // non-Ember (or hostile) peer we're downloading from could
                // inject crafted source/peer hints into our mesh
                // (`known_ember_peers`, broker relay candidates).
                (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE)
                    if peer_is_ember
                        && epx_packets_received
                            < crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION =>
                {
                    self.sx_overhead.record_download((6 + pl.len()) as u64);
                    epx_packets_received += 1;
                    info!(
                        "Received early EPX from {} during pre-control ({} bytes)",
                        self.source_addr,
                        pl.len()
                    );
                    match crate::network::ember::parse_exchange_payload(&pl) {
                        Ok(result)
                            if !result.files.is_empty()
                                || !result.peers.is_empty()
                                || !result.relay_attestations.is_empty() =>
                        {
                            let (epx_entries, aich_roots) = epx_result_to_entries(&result);
                            let relay_attestations = result.relay_attestations.clone();
                            let epx_peers = result
                                .peers
                                .into_iter()
                                .map(|ep| (ep.ip, ep.tcp_port))
                                .collect();
                            let _ = event_tx
                                .send(DownloadEvent::EmberSources {
                                    transfer_id: self.transfer_id.clone(),
                                    entries: epx_entries,
                                    aich_roots,
                                    ember_peers: epx_peers,
                                    relay_attestations,
                                })
                                .await;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            debug!("Failed to parse early EPX from {}: {e}", self.source_addr)
                        }
                    }
                }
                (OP_EMULEPROT, OP_EMBER_FRIEND_REQ) => {
                    if let Some(eh) = peer_ember_hash {
                        let nick = std::str::from_utf8(&pl).unwrap_or("").to_string();
                        // `verified` requires PoP (Ed25519 challenge-
                        // response). Binding-only is replayable — a
                        // peer who learned a victim's public
                        // (pubkey, ember_hash) on the wire could
                        // otherwise post a "Verified" friend request
                        // in the recipient's UI. PoP also re-runs on
                        // the friend-connect dial-back if the user
                        // accepts, so this never permanently marks a
                        // legitimate friend unverified.
                        let verified = ember_auth_verified;
                        info!(
                            "Received early friend request from {} (nick='{}', verified={verified}, pop={}, binding={ember_hash_binding_verified})",
                            self.source_addr, nick, ember_auth_verified
                        );
                        let _ = event_tx
                            .send(DownloadEvent::EmberFriendRequest {
                                ember_hash: eh,
                                nickname: nick,
                                peer_ip: self.source_addr.ip().to_string(),
                                peer_port: self.source_addr.port(),
                                verified,
                            })
                            .await;
                    }
                }
                // Authoritative Ember peer detection. A peer that emits a
                // parseable `OP_EMBER_HELLO` / `OP_EMBER_HELLOANSWER`
                // payload is, by construction, an Ember client — vanilla
                // eMule never sends either opcode (private 0xF8/0xF9
                // range; `ListenSocket.cpp`'s default branch just logs
                // "Unknown extended emule protocol opcode" and returns).
                // When the peer beat us to it and sent `OP_EMBER_HELLO`
                // (rather than the answer), we respond with our own
                // `OP_EMBER_HELLOANSWER` so they learn our identity in
                // the same round trip.
                (OP_EMULEPROT, OP_EMBER_HELLO) | (OP_EMULEPROT, OP_EMBER_HELLOANSWER) => {
                    if let Some(ident) = parse_ember_hello(&pl) {
                        peer_is_ember = true;
                        // Identity lock: refuse to swap pubkey/hash
                        // after PoP verification (see upload.rs for
                        // the full rationale — same accounting risk).
                        let identity_changed = ember_auth_verified
                            && ((ident.ed25519_pubkey.is_some()
                                && peer_ember_pubkey.is_some()
                                && ident.ed25519_pubkey != peer_ember_pubkey)
                                || (ident.ember_hash != [0u8; 16]
                                    && peer_ember_hash.is_some()
                                    && Some(ident.ember_hash) != peer_ember_hash));
                        if identity_changed {
                            tracing::warn!(
                                "Ember identity-swap rejected from {}: peer already PoP-verified, ignoring re-keyed OP_EMBER_HELLO (old_hash={:?}, new_hash={})",
                                self.source_addr,
                                peer_ember_hash.as_ref().map(hex::encode),
                                hex::encode(ident.ember_hash),
                            );
                        }
                        if ident.ember_hash != [0u8; 16] && !identity_changed {
                            peer_ember_hash = Some(ident.ember_hash);
                        }
                        if let Some(pk) = ident.ed25519_pubkey {
                            if !identity_changed {
                                peer_ember_pubkey = Some(pk);
                            }
                        }
                        if !ident.nickname.is_empty() {
                            peer_name_label = ident.nickname.clone();
                        }
                        debug!(
                            "Peer {} identified as Ember via OP_EMBER_HELLO (mod='{}', nick='{}')",
                            self.source_addr, ident.mod_version, ident.nickname
                        );
                        if o == OP_EMBER_HELLO && !sent_ember_hello {
                            // Advertise our pubkey so the peer can run
                            // `verify_ember_hash_binding` on us
                            // symmetrically. Vanilla peers ignore the
                            // opcode, so this is safe to emit whenever
                            // we're responding to a peer-initiated
                            // Ember-Hello.
                            let payload = build_ember_hello(
                                &self.ember_hash,
                                &self.our_nickname,
                                Some(&self.ed25519_public_key),
                            );
                            let _ = write_packet_async(
                                &mut writer,
                                OP_EMULEPROT,
                                OP_EMBER_HELLOANSWER,
                                &payload,
                            )
                            .await;
                            sent_ember_hello = true;
                        }

                        // Offline identity-binding check first — cheap,
                        // and we need it regardless of whether the
                        // peer supports the full challenge-response.
                        if !ember_hash_binding_verified {
                            if let (Some(ref pk), Some(ref eh)) =
                                (peer_ember_pubkey, peer_ember_hash)
                            {
                                if crate::network::ember::crypto::verify_ember_hash_binding(pk, eh)
                                {
                                    ember_hash_binding_verified = true;
                                    info!(
                                        "Ember binding: peer {} pubkey BLAKE3-binds to advertised hash",
                                        self.source_addr
                                    );
                                } else {
                                    tracing::warn!(
                                        "Ember binding: peer {} advertised pubkey does not BLAKE3-bind to ember_hash={} (possible spoof)",
                                        self.source_addr,
                                        hex::encode(eh)
                                    );
                                }
                            }
                        }

                        // Full Ed25519 proof-of-possession via the
                        // packet-buffering auth wrapper. Mirrors the
                        // multi_source.rs pre-control flow: only
                        // attempt PoP when the binding check passed
                        // (don't leak our nonce to hash-spoofers) and
                        // we haven't already verified on this session.
                        // Captured non-AUTH packets are pushed into
                        // `auth_deferred` and replayed at the top of
                        // this loop on subsequent iterations, so the
                        // uploader's OP_SECIDENTSTATE / EPX bundled
                        // with its auth response still flow through
                        // the normal match arms.
                        //
                        // PoP failure is non-fatal — the download
                        // itself is separable from identity
                        // verification. We just leave
                        // `ember_auth_verified = false` so
                        // `DownloadEvent::EmberFriendRequest.verified`
                        // falls back to the binding-only signal.
                        if !ember_auth_verified && ember_hash_binding_verified {
                            if let (Some(peer_pk), Some(peer_eh)) =
                                (peer_ember_pubkey, peer_ember_hash)
                            {
                                match super::friend_connect::perform_ember_auth_buffered(
                                    &mut reader,
                                    &mut writer,
                                    &self.ed25519_public_key,
                                    &self.ed25519_secret_key,
                                    &peer_pk,
                                    Some(&peer_eh),
                                    self.source_addr,
                                    &mut auth_deferred,
                                )
                                .await
                                {
                                    Ok(()) => {
                                        ember_auth_verified = true;
                                        info!(
                                            "Ember auth: peer {} verified via PoP ({} deferred packet(s) queued for replay)",
                                            self.source_addr,
                                            auth_deferred.len()
                                        );
                                        // Pre-control PoP runs before
                                        // `peer_is_friend` is bound,
                                        // so re-check `friend_hashes`
                                        // inline to gate the
                                        // FriendSeen emit on PoP.
                                        if !friend_seen_emitted {
                                            if let (Some(ref fh_arc), Some(eh)) =
                                                (&self.friend_hashes, peer_ember_hash)
                                            {
                                                if fh_arc.read().await.contains(&eh) {
                                                    let _ = event_tx
                                                        .send(DownloadEvent::FriendSeen {
                                                            ember_hash: eh,
                                                            ip: self.source_addr.ip(),
                                                            port: self.source_addr.port(),
                                                        })
                                                        .await;
                                                    friend_seen_emitted = true;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Ember auth: peer {} PoP failed — continuing with binding-only verification: {e}",
                                            self.source_addr
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {
                    deferred_packet = Some((p, o, pl));
                    break;
                }
            }
        }

        // Send our `OP_EMBER_HELLO` unconditionally so any real Ember
        // peer can BLAKE3-bind our advertised identity — mirrors the
        // unconditional send in `multi_source.rs`. Vanilla eMule peers
        // silently ignore the unknown opcode (`ListenSocket.cpp`'s
        // ProcessExtPacket default branch just logs + returns), so
        // this is invisible to non-Ember clients and keeps our public
        // handshake byte-identical to vanilla eMule (important for
        // anti-leecher queue-ban avoidance).
        //
        // Skipped if the peer beat us to it during the pre-control
        // loop above (we replied with HELLOANSWER there and set
        // `sent_ember_hello = true`). Otherwise the peer's
        // HELLOANSWER will land in the file-status-wait loop below
        // and set `peer_is_ember = true`, populate
        // `peer_ember_pubkey`, and flip `ember_hash_binding_verified`
        // when the BLAKE3 check passes.
        if !sent_ember_hello {
            let payload = build_ember_hello(
                &self.ember_hash,
                &self.our_nickname,
                Some(&self.ed25519_public_key),
            );
            if write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_HELLO, &payload)
                .await
                .is_ok()
            {
                sent_ember_hello = true;
            }
        }

        // Ember Peer Exchange: if peer is a Ember client, send our source list.
        // Snapshot the generation we sent so the periodic-resend loop below
        // can detect rebuilds that happen during file-status / queue wait.
        // (See `multi_source.rs` for the symmetric fix.)
        let mut initial_epx_sent_generation: Option<u64> = None;
        if peer_is_ember {
            let sent_gen = self
                .ember_payload_generation
                .load(std::sync::atomic::Ordering::Relaxed);
            let epx_data = self.ember_payload.read().await.clone();
            if !epx_data.is_empty() {
                debug!(
                    "Sending Ember Peer Exchange to {} ({} bytes, gen {})",
                    self.source_addr,
                    epx_data.len(),
                    sent_gen
                );
                let _ = write_packet_async(
                    &mut writer,
                    OP_EMULEPROT,
                    OP_EMBER_SOURCEEXCHANGE,
                    &*epx_data,
                )
                .await;
                self.sx_overhead.record_upload((6 + epx_data.len()) as u64);
                initial_epx_sent_generation = Some(sent_gen);
            }
            if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                let peer_tcp = self.source_addr.port();
                if peer_tcp > 0 && !crate::security::is_special_use_v4(v4) {
                    let _ = event_tx
                        .send(DownloadEvent::EmberPeerDiscovered {
                            ip: v4,
                            tcp_port: peer_tcp,
                        })
                        .await;
                }
            }
        }

        let peer_is_friend =
            if let (Some(ref fh), Some(eh)) = (&self.friend_hashes, peer_ember_hash) {
                fh.read().await.contains(&eh)
            } else {
                false
            };
        if peer_is_ember && peer_is_friend {
            let nick_bytes = self.our_nickname.as_bytes();
            let _ = write_packet_async(&mut writer, OP_EMULEPROT, OP_EMBER_FRIEND_REQ, nick_bytes)
                .await;
        }
        // FriendSeen emit is deferred to PoP-success sites. The
        // dispatcher promotes FriendSeen to `update_friend_address`
        // (overwriting the friend's last known IP) and an
        // `ember:friend-online` UI event; both are user-facing facts
        // about *that friend*, so they require Ed25519 PoP, not just
        // the unauthenticated `is_friend && hello_caps.is_ember` claim.
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
            } else {
                true
            }
        } else {
            true
        };

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
            write_packet_async(
                &mut writer,
                OP_EDONKEYHEADER,
                OP_REQUESTFILENAME,
                &req_file_name_payload,
            )
            .await?;
            if !single_part {
                write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_SETREQFILEID, &file_req)
                    .await?;
            }
        }

        // Read FileStatus and FileName responses
        let mut got_status = single_part;
        let mut got_filename = false;
        let mut available_parts: Vec<bool> = if single_part { vec![true] } else { Vec::new() };

        for _ in 0..12 {
            let (proto, opcode, payload) = if let Some(pkt) = deferred_packet.take() {
                pkt
            } else if let Some(pkt) = auth_deferred.pop_front() {
                // Drain any remaining auth-captured packets before
                // reading fresh bytes off the stream. Same rationale
                // as the pre-control loop above: the uploader's
                // proactive opcodes must be processed in arrival
                // order so SecIdent state stays consistent.
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
                        debug!(
                            "FileStatus: part_count=0 → peer has complete file ({} parts)",
                            part_count
                        );
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
                                sm.register_source_full(
                                    self.file_hash,
                                    v4,
                                    self.source_addr.port(),
                                    peer_udp,
                                    peer_user_hash,
                                );
                            }
                        }
                    }
                    if opcode == OP_EMULEINFO {
                        let emule_answer = build_emule_info(
                            self.udp_port,
                            self.obfuscation_enabled,
                            Some(&self.ember_hash),
                            None,
                        );
                        let _ = write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_EMULEINFOANSWER,
                            &emule_answer,
                        )
                        .await;
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
                        )
                        .await?;
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
                        our_client_id,
                    )
                    .await?;
                }
                (OP_EMULEPROT, OP_SIGNATURE) if payload.len() >= 2 => {
                    handle_secident_signature(
                        self.credit_manager.as_ref(),
                        peer_user_hash,
                        &mut pending_secident_challenge,
                        self.source_addr,
                        peer_secure_ident_level,
                        &payload,
                        our_client_id,
                    )
                    .await;
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
                            || mp
                                .file_identifier
                                .as_ref()
                                .map(|id| !local_ident.compare_relaxed(id))
                                .unwrap_or(false)
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
                // Ember-only; gated on `peer_is_ember` (see upload.rs).
                (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE) if peer_is_ember => {
                    self.sx_overhead.record_download((6 + payload.len()) as u64);
                    if epx_packets_received >= crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION
                    {
                        debug!("Ignoring excess EPX packet from {}", self.source_addr);
                    } else {
                        epx_packets_received += 1;
                        match crate::network::ember::parse_exchange_payload(&payload) {
                            Ok(result)
                                if !result.files.is_empty()
                                    || !result.peers.is_empty()
                                    || !result.relay_attestations.is_empty() =>
                            {
                                info!(
                                    "Received Ember Peer Exchange from {} ({} files, {} peers, {} relay attestations)",
                                    self.source_addr,
                                    result.files.len(),
                                    result.peers.len(),
                                    result.relay_attestations.len()
                                );
                                let (epx_entries, aich_roots) = epx_result_to_entries(&result);
                                let relay_attestations = result.relay_attestations.clone();
                                let ember_peers = result
                                    .peers
                                    .into_iter()
                                    .map(|p| (p.ip, p.tcp_port))
                                    .collect();
                                let _ = event_tx
                                    .send(DownloadEvent::EmberSources {
                                        transfer_id: self.transfer_id.clone(),
                                        entries: epx_entries,
                                        aich_roots,
                                        ember_peers,
                                        relay_attestations,
                                    })
                                    .await;
                            }
                            Ok(_) => {}
                            Err(e) => debug!(
                                "Failed to parse Ember exchange from {}: {e}",
                                self.source_addr
                            ),
                        }
                    }
                }
                (OP_EMULEPROT, OP_EMBER_FRIEND_REQ) if peer_is_ember => {
                    if let Some(eh) = peer_ember_hash {
                        let nick = std::str::from_utf8(&payload).unwrap_or("").to_string();
                        // Prefer the full PoP signal over the
                        // binding-only fallback. Both flags are set in
                        // the OP_EMBER_HELLO arms above / in the
                        // pre-control loop, so by the time we reach
                        // file-status-wait most well-behaved peers
                        // have already flipped `ember_auth_verified`.
                        // PoP-only (binding is replayable; see early
                        // friend-request site).
                        let verified = ember_auth_verified;
                        let _ = event_tx
                            .send(DownloadEvent::EmberFriendRequest {
                                ember_hash: eh,
                                nickname: nick,
                                peer_ip: self.source_addr.ip().to_string(),
                                peer_port: self.source_addr.port(),
                                verified,
                            })
                            .await;
                    }
                }
                // Peer may delay their `OP_EMBER_HELLOANSWER` past the
                // pre-control loop — in which case it lands here.
                // Same handling: update identity, run the offline
                // binding check, echo our HELLOANSWER if they sent
                // a HELLO rather than an answer.
                (OP_EMULEPROT, OP_EMBER_HELLO) | (OP_EMULEPROT, OP_EMBER_HELLOANSWER) => {
                    if let Some(ident) = parse_ember_hello(&payload) {
                        peer_is_ember = true;
                        // Identity lock (see pre-control arm).
                        let identity_changed = ember_auth_verified
                            && ((ident.ed25519_pubkey.is_some()
                                && peer_ember_pubkey.is_some()
                                && ident.ed25519_pubkey != peer_ember_pubkey)
                                || (ident.ember_hash != [0u8; 16]
                                    && peer_ember_hash.is_some()
                                    && Some(ident.ember_hash) != peer_ember_hash));
                        if identity_changed {
                            tracing::warn!(
                                "Ember identity-swap rejected from {} (file-status-wait): peer already PoP-verified",
                                self.source_addr,
                            );
                        }
                        if ident.ember_hash != [0u8; 16] && !identity_changed {
                            peer_ember_hash = Some(ident.ember_hash);
                        }
                        if let Some(pk) = ident.ed25519_pubkey {
                            if !identity_changed {
                                peer_ember_pubkey = Some(pk);
                            }
                        }
                        if !ident.nickname.is_empty() {
                            peer_name_label = ident.nickname.clone();
                        }
                        debug!(
                            "Peer {} identified as Ember via OP_EMBER_HELLO during file-status-wait (mod='{}', nick='{}')",
                            self.source_addr, ident.mod_version, ident.nickname
                        );
                        if opcode == OP_EMBER_HELLO && !sent_ember_hello {
                            let payload = build_ember_hello(
                                &self.ember_hash,
                                &self.our_nickname,
                                Some(&self.ed25519_public_key),
                            );
                            let _ = write_packet_async(
                                &mut writer,
                                OP_EMULEPROT,
                                OP_EMBER_HELLOANSWER,
                                &payload,
                            )
                            .await;
                            sent_ember_hello = true;
                        }
                        if !ember_hash_binding_verified {
                            if let (Some(ref pk), Some(ref eh)) =
                                (peer_ember_pubkey, peer_ember_hash)
                            {
                                if crate::network::ember::crypto::verify_ember_hash_binding(pk, eh)
                                {
                                    ember_hash_binding_verified = true;
                                    info!(
                                        "Ember binding: peer {} pubkey BLAKE3-binds (file-status-wait)",
                                        self.source_addr
                                    );
                                } else {
                                    tracing::warn!(
                                        "Ember binding: peer {} advertised pubkey does not BLAKE3-bind to ember_hash={} (file-status-wait, possible spoof)",
                                        self.source_addr,
                                        hex::encode(eh)
                                    );
                                }
                            }
                        }

                        // Run PoP here too in case the peer delayed
                        // OP_EMBER_HELLOANSWER past the pre-control
                        // loop. Same buffering rationale: captured
                        // non-AUTH frames are drained on subsequent
                        // iterations of this file-status-wait loop.
                        if !ember_auth_verified && ember_hash_binding_verified {
                            if let (Some(peer_pk), Some(peer_eh)) =
                                (peer_ember_pubkey, peer_ember_hash)
                            {
                                match super::friend_connect::perform_ember_auth_buffered(
                                    &mut reader,
                                    &mut writer,
                                    &self.ed25519_public_key,
                                    &self.ed25519_secret_key,
                                    &peer_pk,
                                    Some(&peer_eh),
                                    self.source_addr,
                                    &mut auth_deferred,
                                )
                                .await
                                {
                                    Ok(()) => {
                                        ember_auth_verified = true;
                                        info!(
                                            "Ember auth: peer {} verified via PoP during file-status-wait ({} deferred packet(s) queued for replay)",
                                            self.source_addr,
                                            auth_deferred.len()
                                        );
                                        if !friend_seen_emitted {
                                            if let (true, Some(eh)) =
                                                (peer_is_friend, peer_ember_hash)
                                            {
                                                let _ = event_tx
                                                    .send(DownloadEvent::FriendSeen {
                                                        ember_hash: eh,
                                                        ip: self.source_addr.ip(),
                                                        port: self.source_addr.port(),
                                                    })
                                                    .await;
                                                friend_seen_emitted = true;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Ember auth: peer {} PoP failed (file-status-wait) — continuing with binding-only verification: {e}",
                                            self.source_addr
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                (OP_EMULEPROT, OP_EMBER_CHAT_MSG)
                    if is_ember_friend && ember_auth_verified && payload.len() <= 4096 =>
                {
                    if let Some(eh) = peer_ember_hash {
                        if let Ok(msg) = std::str::from_utf8(&payload) {
                            let _ = event_tx
                                .send(DownloadEvent::EmberChatMessage {
                                    ember_hash: eh,
                                    message: msg.to_string(),
                                })
                                .await;
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

        let src_avail_parts: Option<u32> =
            Some(available_parts.iter().filter(|&&p| p).count() as u32);
        let src_total_parts: Option<u32> = Some(available_parts.len() as u32);

        // Request part hashset for verification
        if peer_supports_file_ident {
            let hashset_req2 =
                build_hashset_request2(&self.file_hash, self.file_size, None, true, false);
            write_packet_async(&mut writer, OP_EMULEPROT, OP_HASHSETREQUEST2, &hashset_req2)
                .await?;
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
                                    debug!(
                                        "Got verified hashset with {} part hashes",
                                        hashes.len()
                                    );
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
                                        debug!(
                                            "Got verified hashset2 with {} part hashes",
                                            hashes.len()
                                        );
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
        if !(peer_supports_file_ident || peer_supports_ext_multipacket || peer_supports_multipacket)
            && sx_allowed
        {
            if peer_supports_source_ex2 {
                let mut sx2_req = Vec::with_capacity(19);
                sx2_req.push(SOURCEEXCHANGE2_VERSION);
                sx2_req.extend_from_slice(&0u16.to_le_bytes());
                sx2_req.extend_from_slice(&self.file_hash);
                write_packet_async(&mut writer, OP_EMULEPROT, OP_REQUESTSOURCES2, &sx2_req).await?;
                self.sx_overhead.record_upload((6 + sx2_req.len()) as u64);
            } else {
                let sx_req = build_file_request(&self.file_hash);
                write_packet_async(&mut writer, OP_EMULEPROT, OP_REQUESTSOURCES, &sx_req).await?;
                self.sx_overhead.record_upload((6 + sx_req.len()) as u64);
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
            self.emit_source_detail_parts(
                event_tx,
                "transferring",
                None,
                0,
                0,
                &client_software_label,
                &peer_name_label,
                src_avail_parts,
                src_total_parts,
            )
            .await;
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
            write_packet_async(
                &mut writer,
                OP_EDONKEYHEADER,
                OP_STARTUPLOADREQ,
                &upload_req,
            )
            .await?;

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
            self.emit_source_detail_parts(
                event_tx,
                "queued",
                None,
                0,
                0,
                &client_software_label,
                &peer_name_label,
                src_avail_parts,
                src_total_parts,
            )
            .await;

            loop {
                self.check_control().await?;

                let qwait = self.ed2k_limits.queue_wait_secs;
                if queue_start.elapsed().as_secs() > qwait {
                    anyhow::bail!(
                        "stage:queue_wait timed out waiting for upload slot after {qwait}s"
                    );
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
                    Ok(Err(e)) => {
                        anyhow::bail!("stage:queue_detached connection lost while queued: {e}")
                    }
                    Err(_) => {
                        anyhow::bail!(
                            "stage:queue_wait timed out waiting for upload slot after {qwait}s"
                        );
                    }
                };

                if proto == OP_EDONKEYHEADER && opcode == OP_ACCEPTUPLOADREQ {
                    debug!("Upload accepted");
                    self.emit_source_detail_parts(
                        event_tx,
                        "transferring",
                        None,
                        0,
                        0,
                        &client_software_label,
                        &peer_name_label,
                        src_avail_parts,
                        src_total_parts,
                    )
                    .await;
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
                    self.emit_source_detail_parts(
                        event_tx,
                        "queue_full",
                        None,
                        0,
                        0,
                        &client_software_label,
                        &peer_name_label,
                        src_avail_parts,
                        src_total_parts,
                    )
                    .await;
                    anyhow::bail!("stage:queue_wait peer queue is full");
                }

                if proto == OP_EMULEPROT && opcode == OP_QUEUERANKING && payload.len() >= 2 {
                    let rank = u16::from_le_bytes([payload[0], payload[1]]);
                    info!("Queued at position {} on peer {}", rank, self.source_addr);
                    self.emit_source_detail_parts(
                        event_tx,
                        "queued",
                        Some(rank as u32),
                        0,
                        0,
                        &client_software_label,
                        &peer_name_label,
                        src_avail_parts,
                        src_total_parts,
                    )
                    .await;
                    continue;
                }

                if proto == OP_EDONKEYHEADER && opcode == OP_QUEUERANK && payload.len() >= 4 {
                    let rank = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    info!(
                        "Queued at position {} on peer {} (legacy)",
                        rank, self.source_addr
                    );
                    self.emit_source_detail_parts(
                        event_tx,
                        "queued",
                        Some(rank),
                        0,
                        0,
                        &client_software_label,
                        &peer_name_label,
                        src_avail_parts,
                        src_total_parts,
                    )
                    .await;
                    continue;
                }

                if proto == OP_EMULEPROT && opcode == OP_ANSWERSOURCES && payload.len() >= 18 {
                    self.sx_overhead.record_download((6 + payload.len()) as u64);
                    match parse_answer_sources(&payload, peer_source_exchange_ver) {
                        Ok((version, answer_hash, entries)) if answer_hash == self.file_hash => {
                            let mut sx_count = 0u32;
                            let mut sx_entries: Vec<SourceExchangeEntry> = Vec::new();
                            for entry in entries {
                                if entry.tcp_port == 0 {
                                    continue;
                                }
                                let uh = entry.user_hash.unwrap_or([0u8; 16]);
                                let co = entry.crypt_options.unwrap_or(0);
                                // LowID source — see the matching block in
                                // `multi_source.rs` for the full rationale.
                                // eMule registers these via the named server
                                // and uses the callback path; dropping them
                                // silently halved our source pool on
                                // LowID-heavy networks.
                                // Normalize to eMule's hybrid (host-order) ID
                                // before classifying — SX versions < 3 send it
                                // byte-swapped, so a raw `< 16M` test would
                                // mis-read a LowID peer as a HighID.
                                let hybrid_id = source_exchange_hybrid_id(version, entry.source_id);
                                if hybrid_id < 16_777_216 {
                                    if entry.server_ip == 0 || entry.server_port == 0 {
                                        continue;
                                    }
                                    if let Some(sm) = &self.source_manager {
                                        let mut sm = sm.write().await;
                                        sm.register_lowid_source(
                                            self.file_hash,
                                            hybrid_id,
                                            entry.tcp_port,
                                            entry.server_ip,
                                            entry.server_port,
                                            uh,
                                            co,
                                        );
                                    }
                                    sx_count += 1;
                                    continue;
                                }
                                let ip = source_exchange_id_to_ipv4(version, entry.source_id);
                                if is_filtered_source_ip(&ip)
                                    || self.is_sx_source_rejected(&ip, entry.tcp_port)
                                {
                                    continue;
                                }
                                if let Some(sm) = &self.source_manager {
                                    let mut sm = sm.write().await;
                                    sm.register_source_full_server(
                                        self.file_hash,
                                        ip,
                                        entry.tcp_port,
                                        0,
                                        entry.server_ip,
                                        entry.server_port,
                                        uh,
                                        co,
                                    );
                                }
                                sx_entries.push(SourceExchangeEntry {
                                    ip,
                                    tcp_port: entry.tcp_port,
                                    user_hash: uh,
                                    crypt_options: co,
                                });
                                sx_count += 1;
                            }
                            if sx_count > 0 {
                                debug!("Legacy source exchange: registered {sx_count} new sources from {}", self.source_addr);
                                let _ = event_tx
                                    .send(DownloadEvent::SourceExchange {
                                        transfer_id: self.transfer_id.clone(),
                                        file_hash: self.file_hash,
                                        sources: sx_entries,
                                    })
                                    .await;
                            }
                        }
                        Ok((_version, answer_hash, _)) => {
                            debug!(
                                "Ignoring OP_ANSWERSOURCES from {} for different file {}",
                                self.source_addr,
                                hex::encode(answer_hash)
                            );
                        }
                        Err(e) => debug!(
                            "Failed to parse OP_ANSWERSOURCES from {}: {e}",
                            self.source_addr
                        ),
                    }
                    continue;
                }

                if proto == OP_EMULEPROT && opcode == OP_ANSWERSOURCES2 && payload.len() >= 19 {
                    self.sx_overhead.record_download((6 + payload.len()) as u64);
                    match parse_answer_sources2(&payload) {
                        Ok((version, answer_hash, entries)) if answer_hash == self.file_hash => {
                            let mut sx_count = 0u32;
                            let mut sx_entries: Vec<SourceExchangeEntry> = Vec::new();
                            for entry in entries {
                                if entry.tcp_port == 0 {
                                    continue;
                                }
                                let uh = entry.user_hash.unwrap_or([0u8; 16]);
                                let co = entry.crypt_options.unwrap_or(0);
                                // Same LowID handling as the SX1 arm above —
                                // register with the named server so the
                                // callback path can reach this peer instead
                                // of dropping it outright.
                                let hybrid_id = source_exchange_hybrid_id(version, entry.source_id);
                                if hybrid_id < 16_777_216 {
                                    if entry.server_ip == 0 || entry.server_port == 0 {
                                        continue;
                                    }
                                    if let Some(sm) = &self.source_manager {
                                        let mut sm = sm.write().await;
                                        sm.register_lowid_source(
                                            self.file_hash,
                                            hybrid_id,
                                            entry.tcp_port,
                                            entry.server_ip,
                                            entry.server_port,
                                            uh,
                                            co,
                                        );
                                    }
                                    sx_count += 1;
                                    continue;
                                }
                                let ip = source_exchange_id_to_ipv4(version, entry.source_id);
                                if is_filtered_source_ip(&ip)
                                    || self.is_sx_source_rejected(&ip, entry.tcp_port)
                                {
                                    continue;
                                }
                                if entry.server_ip != 0 {
                                    debug!(
                                        "SX2 source {} advertises server {:08X}:{}",
                                        ip, entry.server_ip, entry.server_port
                                    );
                                }
                                if let Some(sm) = &self.source_manager {
                                    let mut sm = sm.write().await;
                                    sm.register_source_full_server(
                                        self.file_hash,
                                        ip,
                                        entry.tcp_port,
                                        0,
                                        entry.server_ip,
                                        entry.server_port,
                                        uh,
                                        co,
                                    );
                                }
                                sx_entries.push(SourceExchangeEntry {
                                    ip,
                                    tcp_port: entry.tcp_port,
                                    user_hash: uh,
                                    crypt_options: co,
                                });
                                sx_count += 1;
                            }
                            if sx_count > 0 {
                                debug!(
                                    "Source exchange: registered {sx_count} new sources from {}",
                                    self.source_addr
                                );
                                let _ = event_tx
                                    .send(DownloadEvent::SourceExchange {
                                        transfer_id: self.transfer_id.clone(),
                                        file_hash: self.file_hash,
                                        sources: sx_entries,
                                    })
                                    .await;
                            }
                        }
                        Ok((_version, answer_hash, _)) => {
                            debug!(
                                "Ignoring OP_ANSWERSOURCES2 from {} for different file {}",
                                self.source_addr,
                                hex::encode(answer_hash)
                            );
                        }
                        Err(e) => debug!(
                            "Failed to parse OP_ANSWERSOURCES2 from {}: {e}",
                            self.source_addr
                        ),
                    }
                    continue;
                }

                if proto == OP_EDONKEYHEADER && opcode == OP_OUTOFPARTREQS {
                    info!("Peer rejected with OutOfPartReqs, will retry later");
                    self.emit_source_detail_parts(
                        event_tx,
                        "no_needed_parts",
                        None,
                        0,
                        0,
                        &client_software_label,
                        &peer_name_label,
                        src_avail_parts,
                        src_total_parts,
                    )
                    .await;
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

        // Publish initial preview-readiness onto the shared transfer control so
        // the UI's Preview button is correct on resume (first part already
        // verified on disk). Refreshed below as parts verify.
        self.control
            .set_preview_ready(tracker.is_preview_ready(&self.file_name, self.file_size));

        // Per-file writer: dedicated thread + bounded channel replaces the
        // previous `Arc<Mutex<File>>`-with-`spawn_blocking`-per-block pattern
        // that serialized all writes on a single mutex. See
        // `network::ed2k::write_coordinator` for design notes.
        let output = {
            let completed_bytes = tracker.completed_bytes();
            let completed_parts = tracker.completed_count();
            let total_parts = tracker.part_count;
            let existing_len = if part_path.exists() {
                tokio::fs::metadata(&part_path)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(0)
            } else {
                0
            };
            // Never truncate a non-empty .part when .part.met reports 0 completed bytes
            // (e.g. corrupt/missing metadata) — that would destroy recoverable data.
            let resuming = completed_bytes > 0 || existing_len > 0;
            if resuming {
                if completed_bytes > 0 {
                    info!("Resuming download: {completed_parts}/{total_parts} parts complete");
                } else {
                    warn!(
                        "Preserving non-empty .part ({existing_len} bytes) while resume metadata shows no completed bytes — \
                         .part.met may be missing or corrupt"
                    );
                }
            }
            super::write_coordinator::PartFileWriter::open(
                part_path.clone(),
                super::write_coordinator::OpenMode::CreateOrOpen {
                    set_len_to: if self.file_size > 0 {
                        Some(self.file_size)
                    } else {
                        None
                    },
                    truncate_existing: !resuming,
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("open part file: {e}"))?
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

        // Throttle DownloadEvent::Progress emission. The DB persist side is
        // already throttled (3s), but the Tauri UI emit and the
        // transfer_manager.write() happen per-event, so a fast peer with
        // ~180 KiB blocks otherwise hits the webview hundreds of times per
        // second. ~200 ms is smooth enough for the UI without saturating it.
        let mut last_progress_emit = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_millis(500))
            .unwrap_or_else(std::time::Instant::now);
        const PROGRESS_EMIT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);
        let mut last_epx_resend = std::time::Instant::now();
        // Use the generation we sent at handshake as the resend baseline so
        // any rebuild during file-status / queue wait gets re-sent on the
        // first periodic check. Falls back to current generation when we
        // never sent (peer not Ember, or our payload was empty at the time).
        let mut last_epx_generation = initial_epx_sent_generation.unwrap_or_else(|| {
            self.ember_payload_generation
                .load(std::sync::atomic::Ordering::Relaxed)
        });
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
                    retry_round,
                    max_part_rounds,
                    needed.len()
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
                // D12: credits accrue only for bytes that end up in a
                // verified part. `pending_credit_bytes` accumulates received
                // bytes; on part verification we flush to the credit
                // ledger, on mismatch we drop the tally.
                let mut pending_credit_bytes: u64 = 0;
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
                        (
                            build_request_parts_i64(&self.file_hash, batch),
                            OP_EMULEPROT,
                            OP_REQUESTPARTS_I64,
                        )
                    } else {
                        (
                            build_request_parts(&self.file_hash, batch),
                            OP_EDONKEYHEADER,
                            OP_REQUESTPARTS,
                        )
                    };
                    write_packet_async(&mut writer, req_proto, req_op, &req_payload).await?;
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
                        let current_gen = self
                            .ember_payload_generation
                            .load(std::sync::atomic::Ordering::Relaxed);
                        if current_gen != last_epx_generation {
                            let epx_data = self.ember_payload.read().await.clone();
                            if !epx_data.is_empty() {
                                debug!(
                                    "Re-sending EPX to {} (gen {}->{}, {} bytes)",
                                    self.source_addr,
                                    last_epx_generation,
                                    current_gen,
                                    epx_data.len()
                                );
                                // Only advance the generation marker on a
                                // successful write; otherwise a failed/back-
                                // pressured send would suppress the retry on
                                // the next interval (mirrors upload.rs).
                                if write_packet_async(
                                    &mut writer,
                                    OP_EMULEPROT,
                                    OP_EMBER_SOURCEEXCHANGE,
                                    &*epx_data,
                                )
                                .await
                                .is_ok()
                                {
                                    last_epx_generation = current_gen;
                                    self.sx_overhead.record_upload((6 + epx_data.len()) as u64);
                                }
                            } else {
                                // Empty payload is terminal for this generation
                                // (nothing to send); advance so we don't re-check
                                // the same empty gen every interval.
                                last_epx_generation = current_gen;
                            }
                        }
                        last_epx_resend = std::time::Instant::now();
                    }

                    let read_timeout = if got_any_data {
                        std::time::Duration::from_secs(READ_TIMEOUT_SECS)
                    } else {
                        let elapsed = data_loop_start.elapsed();
                        let budget = std::time::Duration::from_secs(INITIAL_DATA_TIMEOUT_SECS);
                        budget
                            .saturating_sub(elapsed)
                            .max(std::time::Duration::from_secs(1))
                    };

                    let read_outcome = tokio::select! {
                        biased;
                        // User Stop/Cancel (or a network disconnect) landed
                        // while we're actively downloading from this callback
                        // source. Mirror eMule's CPartFile::PauseFile: send
                        // OP_CANCELTRANSFER so the uploader frees our slot
                        // immediately rather than waiting to notice the dropped
                        // TCP socket. Best-effort + time-boxed, then bail.
                        // Fires on Pause too (eMule's PauseFile notifies every
                        // DS_DOWNLOADING source); the Failed handler ignores the
                        // resulting unwind because the transfer is already
                        // marked Paused.
                        _ = self.control.wait_cancel_or_pause() => {
                            let _ = tokio::time::timeout(
                                std::time::Duration::from_millis(400),
                                write_packet_async(
                                    &mut writer, OP_EDONKEYHEADER, OP_CANCELTRANSFER, &[],
                                ),
                            ).await;
                            anyhow::bail!("cancelled by user");
                        }
                        r = tokio::time::timeout(
                            read_timeout,
                            read_packet_async(&mut reader),
                        ) => r,
                    };
                    let (proto, opcode, payload) = match read_outcome {
                        Ok(Ok(pkt)) => pkt,
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_) => {
                            let _ = write_packet_async(
                                &mut writer,
                                OP_EDONKEYHEADER,
                                OP_CANCELTRANSFER,
                                &[],
                            )
                            .await;
                            if !got_any_data {
                                warn!("Source {} accepted transfer but sent no data in {}s — disconnecting",
                                    self.source_addr, INITIAL_DATA_TIMEOUT_SECS);
                                anyhow::bail!(
                                    "peer accepted transfer but sent no data in {}s",
                                    INITIAL_DATA_TIMEOUT_SECS
                                );
                            } else {
                                anyhow::bail!(
                                    "stage:data_wait download timeout: no data for {}s",
                                    READ_TIMEOUT_SECS
                                );
                            }
                        }
                    };

                    match (proto, opcode) {
                        (OP_EMULEPROT, OP_SENDINGPART_I64) | (OP_EDONKEYHEADER, OP_SENDINGPART) => {
                            let (hash, start, end, data) = if opcode == OP_SENDINGPART_I64 {
                                parse_sending_part_i64(&payload)?
                            } else {
                                // D19: a 32-bit SENDINGPART cannot
                                // address past 4 GiB; refuse it for
                                // larger files so a mis-negotiated or
                                // malicious peer can't silently wrap
                                // the offset and corrupt the part.
                                if self.file_size > u32::MAX as u64 {
                                    anyhow::bail!(
                                            "peer sent 32-bit OP_SENDINGPART for a {}-byte file (requires I64)",
                                            self.file_size
                                        );
                                }
                                parse_sending_part_32(&payload)?
                            };
                            if hash != self.file_hash {
                                anyhow::bail!(
                                    "peer sent SENDINGPART for wrong file: expected={} got={}",
                                    hex::encode(self.file_hash),
                                    hex::encode(hash)
                                );
                            }

                            if start >= end
                                || end > self.file_size
                                || data.len() != (end - start) as usize
                            {
                                consecutive_bad_blocks += 1;
                                warn!("Invalid block offsets: start={start}, end={end}, data_len={}, file_size={} (bad streak: {consecutive_bad_blocks})", data.len(), self.file_size);
                                if consecutive_bad_blocks >= MAX_CONSECUTIVE_BAD_BLOCKS {
                                    if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                        let _ = event_tx
                                            .send(DownloadEvent::ProtocolViolation {
                                                sender_ip: v4,
                                                sender_user_hash: Some(peer_user_hash),
                                            })
                                            .await;
                                    }
                                    anyhow::bail!("peer sent {consecutive_bad_blocks} consecutive invalid blocks, disconnecting");
                                }
                                continue;
                            }
                            consecutive_bad_blocks = 0;
                            let piece_len = end - start;
                            self.acquire_download_bandwidth(piece_len).await;

                            // Never overwrite bytes we already have. Write ONLY the
                            // gap sub-ranges of this block, not the whole block: a
                            // duplicate/overlapping (or cross-part) re-send must not
                            // replace already-present, possibly MD4-verified, data on
                            // disk while `part_verified` stays set (which the upload
                            // path then serves as safe). The transfer counters below
                            // still account the full piece.
                            let fill_subranges = tracker.fillable_subranges(start, end);
                            if !fill_subranges.is_empty() {
                                // Per-file writer thread serializes the writes for
                                // us; await is just an mpsc round-trip.
                                for &(gs, ge) in &fill_subranges {
                                    let off = (gs - start) as usize;
                                    let len = (ge - gs) as usize;
                                    output
                                        .write(gs, data[off..off + len].to_vec())
                                        .await
                                        .map_err(|e| anyhow::anyhow!("part write at {gs}: {e}"))?;
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
                                            sender_user_hash: Some(peer_user_hash),
                                        })
                                        .await;
                                }
                            }

                            if !got_any_data {
                                info!(
                                    "Source {} first data received for part {} ({} bytes)",
                                    self.source_addr, part_idx, piece_len
                                );
                                got_any_data = true;
                            }
                            // Count only bytes that actually filled a gap toward the
                            // displayed progress and per-source speed. A duplicate or
                            // overlapping block (empty `fill_subranges`) consumes wire
                            // bandwidth but adds no new data, so charging `downloaded`
                            // and speed the full piece would over-report until the next
                            // `tracker.completed_bytes()` correction. `total_received`
                            // still tracks wire bytes — the round's exit condition
                            // compares it against what the peer announced it would send.
                            let newly_written: u64 =
                                fill_subranges.iter().map(|(gs, ge)| ge - gs).sum();
                            total_received += piece_len;
                            downloaded += newly_written;
                            blocks_received_in_current_req += 1;
                            speed_measure_bytes += newly_written;

                            // D12: defer credit until the part verifies. Credit only
                            // the bytes actually written (gap-overlap sub-ranges), not
                            // the full wire piece — a duplicate/overlapping block adds
                            // no new data and must not inflate the peer's credit.
                            pending_credit_bytes =
                                pending_credit_bytes.saturating_add(newly_written);

                            if last_progress_emit.elapsed() >= PROGRESS_EMIT_INTERVAL {
                                let _ = event_tx
                                    .send(DownloadEvent::Progress {
                                        transfer_id: self.transfer_id.clone(),
                                        downloaded: downloaded.min(self.file_size),
                                        total: self.file_size,
                                    })
                                    .await;
                                last_progress_emit = std::time::Instant::now();
                            }
                        }
                        (OP_EMULEPROT, OP_COMPRESSEDPART_I64)
                        | (OP_EMULEPROT, OP_COMPRESSEDPART) => {
                            let (hash, start, compressed_total_size, compressed) = if opcode
                                == OP_COMPRESSEDPART_I64
                            {
                                parse_compressed_part_i64(&payload)?
                            } else {
                                // D19 (compressed): a 32-bit OP_COMPRESSEDPART
                                // cannot address past 4 GiB. eMule sends
                                // OP_COMPRESSEDPART_I64 for large files (see
                                // CUpDownClient::CreatePackedPackets), so a
                                // 32-bit frame for a >4 GiB file would have its
                                // start offset truncated by parse_compressed_part_32
                                // and mis-write the .part. Reject rather than wrap.
                                if self.file_size > u32::MAX as u64 {
                                    anyhow::bail!(
                                            "peer sent 32-bit OP_COMPRESSEDPART for a {}-byte file (requires I64)",
                                            self.file_size
                                        );
                                }
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
                            )?
                            else {
                                continue;
                            };

                            let piece_len = decompressed.len() as u64;
                            if start.saturating_add(piece_len) > self.file_size {
                                consecutive_bad_blocks += 1;
                                warn!("Compressed block exceeds file size: start={start}, len={piece_len}, file_size={} (bad streak: {consecutive_bad_blocks})", self.file_size);
                                if consecutive_bad_blocks >= MAX_CONSECUTIVE_BAD_BLOCKS {
                                    if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                        let _ = event_tx
                                            .send(DownloadEvent::ProtocolViolation {
                                                sender_ip: v4,
                                                sender_user_hash: Some(peer_user_hash),
                                            })
                                            .await;
                                    }
                                    anyhow::bail!("peer sent {consecutive_bad_blocks} consecutive invalid blocks, disconnecting");
                                }
                                continue;
                            }
                            consecutive_bad_blocks = 0;
                            self.acquire_download_bandwidth(piece_len).await;

                            // D21 (compressed): write ONLY the gap sub-ranges of the
                            // decompressed block, never the whole block — see the
                            // uncompressed branch above. Prevents an overlapping or
                            // cross-part block from clobbering verified bytes.
                            let fill_subranges =
                                tracker.fillable_subranges(start, start + piece_len);
                            if !fill_subranges.is_empty() {
                                for &(gs, ge) in &fill_subranges {
                                    let off = (gs - start) as usize;
                                    let len = (ge - gs) as usize;
                                    output
                                        .write(gs, decompressed[off..off + len].to_vec())
                                        .await
                                        .map_err(|e| anyhow::anyhow!("part write at {gs}: {e}"))?;
                                }
                                tracker.fill_range(start, start + piece_len);

                                if let std::net::IpAddr::V4(v4) = self.source_addr.ip() {
                                    let _ = event_tx
                                        .send(DownloadEvent::DataReceived {
                                            file_hash: self.file_hash,
                                            start,
                                            end: start + piece_len,
                                            sender_ip: v4,
                                            sender_user_hash: Some(peer_user_hash),
                                        })
                                        .await;
                                }
                            }

                            if !got_any_data {
                                info!("Source {} first compressed data received for part {} ({} bytes)", self.source_addr, part_idx, piece_len);
                                got_any_data = true;
                            }
                            // See the uncompressed branch: only gap-filling bytes
                            // advance displayed progress and speed; duplicate/overlap
                            // blocks add wire bytes (counted in `total_received` for
                            // the round-exit check) but no new data.
                            let newly_written: u64 =
                                fill_subranges.iter().map(|(gs, ge)| ge - gs).sum();
                            total_received += piece_len;
                            downloaded += newly_written;
                            blocks_received_in_current_req += 1;
                            speed_measure_bytes += newly_written;

                            // D12: defer credit until the part verifies. Credit only
                            // the bytes actually written (gap-overlap sub-ranges), not
                            // the full wire piece — a duplicate/overlapping block adds
                            // no new data and must not inflate the peer's credit.
                            pending_credit_bytes =
                                pending_credit_bytes.saturating_add(newly_written);

                            if last_progress_emit.elapsed() >= PROGRESS_EMIT_INTERVAL {
                                let _ = event_tx
                                    .send(DownloadEvent::Progress {
                                        transfer_id: self.transfer_id.clone(),
                                        downloaded: downloaded.min(self.file_size),
                                        total: self.file_size,
                                    })
                                    .await;
                                last_progress_emit = std::time::Instant::now();
                            }
                        }
                        (OP_EDONKEYHEADER, OP_OUTOFPARTREQS) => {
                            info!("Peer session limit reached (OutOfPartReqs), will re-queue");
                            peer_out_of_parts = true;
                            break;
                        }
                        (OP_EMULEPROT, OP_QUEUEFULL) if payload.is_empty() => {
                            self.emit_source_detail_parts(
                                event_tx,
                                "queue_full",
                                None,
                                0,
                                0,
                                &client_software_label,
                                &peer_name_label,
                                src_avail_parts,
                                src_total_parts,
                            )
                            .await;
                            anyhow::bail!("peer revoked upload slot (QueueFull during transfer)");
                        }
                        (OP_EMULEPROT, OP_QUEUERANKING) if payload.len() >= 2 => {
                            let rank = u16::from_le_bytes([payload[0], payload[1]]);
                            self.emit_source_detail_parts(
                                event_tx,
                                "queued",
                                Some(rank as u32),
                                0,
                                0,
                                &client_software_label,
                                &peer_name_label,
                                src_avail_parts,
                                src_total_parts,
                            )
                            .await;
                            anyhow::bail!(
                                "peer put us back in queue at rank {} during transfer",
                                rank
                            );
                        }
                        (OP_EDONKEYHEADER, OP_QUEUERANK) if payload.len() >= 4 => {
                            let rank = u32::from_le_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]);
                            self.emit_source_detail_parts(
                                event_tx,
                                "queued",
                                Some(rank),
                                0,
                                0,
                                &client_software_label,
                                &peer_name_label,
                                src_avail_parts,
                                src_total_parts,
                            )
                            .await;
                            anyhow::bail!(
                                "peer put us back in queue at rank {} during transfer",
                                rank
                            );
                        }
                        (OP_EDONKEYHEADER, OP_FILEREQANSNOFIL) => {
                            anyhow::bail!(
                                "peer no longer has the file (FileNotFound during transfer)"
                            );
                        }
                        (OP_EMULEPROT, OP_PUBLICKEY) if !payload.is_empty() => {
                            let key =
                                if payload.len() >= 2 && payload[0] as usize == payload.len() - 1 {
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
                                )
                                .await?;
                            }
                        }
                        (OP_EMULEPROT, OP_SECIDENTSTATE) if payload.len() >= 5 => {
                            respond_to_secident_challenge(
                                &mut writer,
                                self.credit_manager.as_ref(),
                                payload[0],
                                u32::from_le_bytes([
                                    payload[1], payload[2], payload[3], payload[4],
                                ]),
                                self.source_addr,
                                peer_user_hash,
                                peer_secure_ident_level,
                                our_client_id,
                            )
                            .await?;
                        }
                        (OP_EMULEPROT, OP_SIGNATURE) if payload.len() >= 2 => {
                            handle_secident_signature(
                                self.credit_manager.as_ref(),
                                peer_user_hash,
                                &mut pending_secident_challenge,
                                self.source_addr,
                                peer_secure_ident_level,
                                &payload,
                                our_client_id,
                            )
                            .await;
                        }
                        // eMule OP_FILEDESC: peer sends comment/rating for the file
                        (OP_EMULEPROT, OP_FILEDESC) if payload.len() >= 5 => {
                            let rating = payload[0];
                            // The declared comment length is an attacker-controlled
                            // u32 bounded only by the (multi-MiB) packet size, so
                            // clamp it before reading/allocating: eMule file comments
                            // are short, and an unbounded `String` build is a cheap
                            // per-packet memory-pressure vector.
                            const MAX_PEER_COMMENT_LEN: usize = 8 * 1024;
                            let comment_len = (u32::from_le_bytes([
                                payload[1], payload[2], payload[3], payload[4],
                            ]) as usize)
                                .min(MAX_PEER_COMMENT_LEN);
                            if comment_len
                                .checked_add(5)
                                .map_or(false, |need| payload.len() >= need)
                            {
                                let comment = String::from_utf8_lossy(&payload[5..5 + comment_len])
                                    .to_string();
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
                        // AICH recovery answer from peer. Bound the payload the
                        // same way `wait_for_aich_recovery_answer` does: the
                        // recovery blob can't legitimately exceed
                        // MAX_AICH_RECOVERY_BYTES, and without the upper bound a
                        // peer (who knows the public master hash) could force a
                        // multi-MB allocation held until part verification.
                        (OP_EMULEPROT, OP_AICHANSWER)
                            if (38..=38 + crate::network::ed2k::aich::MAX_AICH_RECOVERY_BYTES)
                                .contains(&payload.len()) =>
                        {
                            let mut ans_hash = [0u8; 16];
                            ans_hash.copy_from_slice(&payload[..16]);
                            let ans_part = u16::from_le_bytes([payload[16], payload[17]]) as usize;
                            let mut root_hash = [0u8; 20];
                            root_hash.copy_from_slice(&payload[18..38]);
                            let recovery_data = &payload[38..];
                            debug!(
                                "AICH answer: part={}, root={}, recovery={} bytes",
                                ans_part,
                                hex::encode(root_hash),
                                recovery_data.len()
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
                        // Ember-only; gated on `peer_is_ember` (see upload.rs).
                        (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE) if peer_is_ember => {
                            self.sx_overhead.record_download((6 + payload.len()) as u64);
                            if epx_packets_received
                                >= crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION
                            {
                                debug!(
                                    "Ignoring excess EPX packet during download from {}",
                                    self.source_addr
                                );
                            } else {
                                epx_packets_received += 1;
                                match crate::network::ember::parse_exchange_payload(&payload) {
                                    Ok(result)
                                        if !result.files.is_empty()
                                            || !result.peers.is_empty()
                                            || !result.relay_attestations.is_empty() =>
                                    {
                                        info!("Received Ember Peer Exchange during download from {} ({} files, {} peers, {} relay attestations)", self.source_addr, result.files.len(), result.peers.len(), result.relay_attestations.len());
                                        let (epx_entries, aich_roots) =
                                            epx_result_to_entries(&result);
                                        let relay_attestations = result.relay_attestations.clone();
                                        let ember_peers = result
                                            .peers
                                            .into_iter()
                                            .map(|p| (p.ip, p.tcp_port))
                                            .collect();
                                        let _ = event_tx
                                            .send(DownloadEvent::EmberSources {
                                                transfer_id: self.transfer_id.clone(),
                                                entries: epx_entries,
                                                aich_roots,
                                                ember_peers,
                                                relay_attestations,
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
                                // By the time we reach the data loop
                                // the peer's Ember-Hello + PoP has
                                // usually completed in an earlier
                                // phase, so `ember_auth_verified` is
                                // the normal signal here. PoP-only —
                                // binding is replayable from public
                                // (pubkey, ember_hash) leaks (KAD,
                                // EPX, public trackers).
                                let verified = ember_auth_verified;
                                let _ = event_tx
                                    .send(DownloadEvent::EmberFriendRequest {
                                        ember_hash: eh,
                                        nickname: nick,
                                        peer_ip: self.source_addr.ip().to_string(),
                                        peer_port: self.source_addr.port(),
                                        verified,
                                    })
                                    .await;
                            }
                        }
                        // Late Ember-Hello during the data loop. Some
                        // peers defer OP_EMBER_HELLOANSWER well past
                        // the handshake / file-status phases (e.g. Ember
                        // clients that wait for the first data exchange
                        // before publishing their identity). Handling
                        // it here keeps the binding flag accurate for
                        // any post-data friend requests.
                        (OP_EMULEPROT, OP_EMBER_HELLO) | (OP_EMULEPROT, OP_EMBER_HELLOANSWER) => {
                            if let Some(ident) = parse_ember_hello(&payload) {
                                peer_is_ember = true;
                                // Identity lock (see pre-control arm).
                                let identity_changed = ember_auth_verified
                                    && ((ident.ed25519_pubkey.is_some()
                                        && peer_ember_pubkey.is_some()
                                        && ident.ed25519_pubkey != peer_ember_pubkey)
                                        || (ident.ember_hash != [0u8; 16]
                                            && peer_ember_hash.is_some()
                                            && Some(ident.ember_hash) != peer_ember_hash));
                                if identity_changed {
                                    tracing::warn!(
                                        "Ember identity-swap rejected from {} (data-loop): peer already PoP-verified",
                                        self.source_addr,
                                    );
                                }
                                if ident.ember_hash != [0u8; 16] && !identity_changed {
                                    peer_ember_hash = Some(ident.ember_hash);
                                }
                                if let Some(pk) = ident.ed25519_pubkey {
                                    if !identity_changed {
                                        peer_ember_pubkey = Some(pk);
                                    }
                                }
                                if opcode == OP_EMBER_HELLO && !sent_ember_hello {
                                    let payload = build_ember_hello(
                                        &self.ember_hash,
                                        &self.our_nickname,
                                        Some(&self.ed25519_public_key),
                                    );
                                    let _ = write_packet_async(
                                        &mut writer,
                                        OP_EMULEPROT,
                                        OP_EMBER_HELLOANSWER,
                                        &payload,
                                    )
                                    .await;
                                    sent_ember_hello = true;
                                }
                                if !ember_hash_binding_verified {
                                    if let (Some(ref pk), Some(ref eh)) =
                                        (peer_ember_pubkey, peer_ember_hash)
                                    {
                                        if crate::network::ember::crypto::verify_ember_hash_binding(
                                            pk, eh,
                                        ) {
                                            ember_hash_binding_verified = true;
                                            info!(
                                                "Ember binding: peer {} pubkey BLAKE3-binds (data loop)",
                                                self.source_addr
                                            );
                                        } else {
                                            tracing::warn!(
                                                "Ember binding: peer {} advertised pubkey does not BLAKE3-bind (data loop, possible spoof)",
                                                self.source_addr
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        (OP_EMULEPROT, OP_EMBER_CHAT_MSG)
                            if is_ember_friend && ember_auth_verified && payload.len() <= 4096 =>
                        {
                            if let Some(eh) = peer_ember_hash {
                                if let Ok(msg) = std::str::from_utf8(&payload) {
                                    let _ = event_tx
                                        .send(DownloadEvent::EmberChatMessage {
                                            ember_hash: eh,
                                            message: msg.to_string(),
                                        })
                                        .await;
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
                                (
                                    build_request_parts_i64(&self.file_hash, batch),
                                    OP_EMULEPROT,
                                    OP_REQUESTPARTS_I64,
                                )
                            } else {
                                (
                                    build_request_parts(&self.file_hash, batch),
                                    OP_EDONKEYHEADER,
                                    OP_REQUESTPARTS,
                                )
                            };
                            write_packet_async(&mut writer, req_proto, req_op, &req_payload)
                                .await?;
                            total_sent_bytes += batch.iter().map(|(s, e)| e - s).sum::<u64>();
                            sent_idx += 1;
                        }
                    }

                    // Update speed measurement every 2 seconds
                    let elapsed = speed_measure_start.elapsed();
                    if elapsed.as_millis() >= 2000 {
                        measured_speed = (speed_measure_bytes as u128 * 1000
                            / elapsed.as_millis().max(1))
                            as u64;
                        speed_measure_bytes = 0;
                        speed_measure_start = std::time::Instant::now();
                        self.emit_source_detail_parts(
                            event_tx,
                            "transferring",
                            None,
                            measured_speed,
                            downloaded,
                            &client_software_label,
                            &peer_name_label,
                            src_avail_parts,
                            src_total_parts,
                        )
                        .await;
                    }

                    if last_periodic_save.elapsed() >= PERIODIC_SAVE_INTERVAL {
                        // Fire-and-forget: snapshot inline, then save on a
                        // blocking thread without awaiting. We don't need
                        // periodic-save to block the receive loop — the
                        // next periodic tick (or the per-part save above)
                        // will catch any failure.
                        let snap = tracker.snapshot_for_save();
                        tokio::task::spawn_blocking(move || {
                            if let Err(e) = snap.write_to_disk() {
                                tracing::warn!("periodic part.met save failed: {e}");
                            }
                        });
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
                    let part_has_gaps = tracker
                        .gap_list()
                        .iter()
                        .any(|&(gs, ge)| gs < pe && ge > ps);
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

                    // Read + MD4 in one writer-thread round-trip — keeps the
                    // hash off the async runtime and avoids re-locking the file.
                    let (part_data, actual_hash) = output
                        .hash_part_md4(ps, part_len)
                        .await
                        .map_err(|e| anyhow::anyhow!("part hash read at {ps}: {e}"))?;

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

                        let mut recovery_bytes: Option<Vec<u8>> =
                            aich_recovery_data.as_ref().map(|(_, d)| d.clone());
                        if let Some(master_hash) = aich_master_hash {
                            if recovery_bytes.is_none() && peer_supports_aich {
                                let aich_should_try = if let std::net::IpAddr::V4(v4) =
                                    self.source_addr.ip()
                                {
                                    if let Some(ref pending) = self.aich_pending {
                                        if let Ok(map) = pending.read() {
                                            match map.get(&(self.file_hash, part_idx as u32)) {
                                                Some((failed_ips, retry_count)) => {
                                                    !failed_ips.contains(&v4) && *retry_count < 3
                                                }
                                                None => true,
                                            }
                                        } else {
                                            true
                                        }
                                    } else {
                                        true
                                    }
                                } else {
                                    true
                                };

                                if aich_should_try {
                                    let mut aich_req = Vec::with_capacity(38);
                                    aich_req.extend_from_slice(&self.file_hash);
                                    aich_req.extend_from_slice(&(part_idx as u16).to_le_bytes());
                                    aich_req.extend_from_slice(&master_hash);
                                    if let Err(e) = write_packet_async(
                                        &mut writer,
                                        OP_EMULEPROT,
                                        OP_AICHREQUEST,
                                        &aich_req,
                                    )
                                    .await
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
                                if let Some(corrupt) =
                                    super::aich::corrupt_blocks_from_aich_recovery(
                                        master_hash,
                                        rec,
                                        part_idx,
                                        &part_data,
                                        part_len,
                                        self.file_size,
                                    )
                                {
                                    if !corrupt.is_empty() {
                                        let (ps, _) = tracker.part_range(part_idx);
                                        let mut invalidated = 0u64;
                                        for &bi in &corrupt {
                                            let rel =
                                                bi as u64 * super::aich::AICH_BLOCK_SIZE as u64;
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
                        // D12: drop the pending credit tally — bytes that
                        // didn't verify earn this peer nothing. Silenced
                        // unused_assignments (compiler can't see the
                        // next-iteration read via saturating_add through
                        // the nested `continue` control flow).
                        #[allow(unused_assignments)]
                        {
                            pending_credit_bytes = 0;
                        }
                        let _ = event_tx
                            .send(DownloadEvent::PartCorrupted {
                                file_hash: self.file_hash,
                                part_start: ps,
                                part_end: pe,
                                sender_user_hash: Some(peer_user_hash),
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
                            sender_user_hash: Some(peer_user_hash),
                        })
                        .await;
                }

                if part_verified {
                    tracker.mark_complete(part_idx);
                    // Flip the persistent verified flag so the upload path
                    // can safely serve this range.
                    tracker.set_part_verified(part_idx);
                    // A newly verified part may make this download previewable
                    // (first part done + media type) — refresh the UI flag.
                    self.control.set_preview_ready(
                        tracker.is_preview_ready(&self.file_name, self.file_size),
                    );
                    // D12: flush the peer's pending credit bytes now that
                    // the part they contributed to actually verified.
                    if pending_credit_bytes > 0 {
                        if let Some(cm) = &self.credit_manager {
                            let mut cm = cm.write().await;
                            cm.add_downloaded(peer_user_hash, pending_credit_bytes);
                            // Mirror for the Ember ledger — same
                            // rationale as `multi_source.rs`. Only
                            // write when the peer completed full
                            // Ed25519 PoP on this session; the
                            // binding-only fallback isn't enough for
                            // long-term credit accumulation (the
                            // PoP is what cryptographically ties the
                            // bytes to the peer's Ed25519 keypair).
                            if let Some(pk) = peer_ember_pubkey {
                                cm.add_ember_downloaded(
                                    pk,
                                    pending_credit_bytes,
                                    ember_auth_verified,
                                );
                            }
                        }
                        #[allow(unused_assignments)]
                        {
                            pending_credit_bytes = 0;
                        }
                    }
                }
                // Force one Progress emit at part boundary so the UI sees
                // verified-part jumps even if the throttle just fired.
                let _ = event_tx
                    .send(DownloadEvent::Progress {
                        transfer_id: self.transfer_id.clone(),
                        downloaded: downloaded.min(self.file_size),
                        total: self.file_size,
                    })
                    .await;
                last_progress_emit = std::time::Instant::now();
                // Save .part.met off-runtime: snapshot under no lock, then
                // run atomic_write on a blocking task. Avoids stalling the
                // download loop on fsync.
                super::part_tracker::save_snapshot_async(tracker.snapshot_for_save()).await;
            }

            // If peer ended the session, reset flag for next retry round
            peer_out_of_parts = false;
        }

        // Signal the uploader that we're done downloading from them
        write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_END_OF_DOWNLOAD, &[])
            .await
            .ok();

        self.emit_source_detail_parts(
            event_tx,
            "completed",
            None,
            measured_speed,
            downloaded.min(self.file_size),
            &client_software_label,
            &peer_name_label,
            src_avail_parts,
            src_total_parts,
        )
        .await;

        if !tracker.all_complete() {
            let remaining = tracker.part_count - tracker.completed_count();
            self.emit_source_failed(
                event_tx,
                &format!("{remaining} parts still failing hash verification"),
                downloaded.min(self.file_size),
                &client_software_label,
                &peer_name_label,
            )
            .await;
            anyhow::bail!(
                "{remaining} parts still failing hash verification after {max_part_rounds} retries"
            );
        }

        // One fsync at completion — the writer thread runs sync_data on the
        // dedicated thread, so we don't block the async runtime here.
        output
            .sync_data()
            .await
            .map_err(|e| anyhow::anyhow!("part file fsync: {e}"))?;
        drop(output);

        let _ = event_tx
            .send(DownloadEvent::Verifying {
                transfer_id: self.transfer_id.clone(),
            })
            .await;

        // Verify the final file hash BEFORE moving the .part file. Always
        // re-read the bytes on disk: a hash derived from known part hashes
        // cannot detect metadata/data divergence after a crash or external
        // Temp-file write.
        let expected_hash = hex::encode(self.file_hash);
        let verify_path = part_path.clone();
        let verified_ok =
            match tokio::task::spawn_blocking(move || super::hash::ed2k_hash_file(&verify_path))
                .await
            {
                Ok(Ok(actual_hash)) if actual_hash == expected_hash => {
                    info!(
                        "Download complete and verified from disk: {}",
                        self.file_name
                    );
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
                    warn!(
                        "Could not verify hash for {}: {e} — treating as failed",
                        self.file_name
                    );
                    false
                }
                Err(e) => {
                    warn!(
                        "Hash verification task failed for {}: {e} — treating as failed",
                        self.file_name
                    );
                    false
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

        // Verification passed — safe to move file and clean up resume state.
        // Flip every part's verified flag (covers single-part < PARTSIZE
        // files that have no per-part hashset, and acts as a belt-and-braces
        // reset for multi-part files).
        tracker.mark_file_hash_verified();
        {
            let pp = part_path.clone();
            let fp = final_path.clone();
            let actual_final = tokio::task::spawn_blocking(move || move_part_to_final(&pp, &fp))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;
            *completed_path_out = Some(actual_final.to_string_lossy().into_owned());
        }
        tracker.delete_met();

        Ok(())
    }

    async fn acquire_download_bandwidth(&self, bytes: u64) {
        self.bandwidth_limiter.acquire_download(bytes).await;
    }
}

/// Per-connection cap on concurrent in-flight compressed blocks. Mirrors
/// the `multi_source.rs` constant and defends against a hostile peer
/// opening many distinct `start` offsets to multiply our buffer memory.
const MAX_PENDING_COMPRESSED_BLOCKS: usize = 16;

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
    if !pending.contains_key(&start) && pending.len() >= MAX_PENDING_COMPRESSED_BLOCKS {
        anyhow::bail!(
            "too many concurrent compressed blocks from peer ({} open, max {})",
            pending.len(),
            MAX_PENDING_COMPRESSED_BLOCKS
        );
    }
    let entry = pending
        .entry(start)
        .or_insert_with(|| PendingCompressedBlock {
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
        // Decompress exactly the declared packed size. The accumulation cap
        // above tolerates a little over-run before bailing, but feeding those
        // trailing padding bytes to the zlib stream can yield a wrong
        // decompressed length (and a mis-sized .part write). eMule sends
        // exactly `total_packed` compressed bytes per block.
        let data = &entry.compressed[..total_packed];
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
            if n == 0 {
                break;
            }
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
            if n == 0 {
                break;
            }
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
) -> anyhow::Result<std::path::PathBuf> {
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
    let actual_final = tokio::task::spawn_blocking(move || move_part_to_final(&pp, &fp))
        .await
        .map_err(|e| anyhow::anyhow!("rename task: {e}"))??;
    Ok(actual_final)
}

fn is_cross_device_error(e: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        matches!(e.raw_os_error(), Some(17))
    } // ERROR_NOT_SAME_DEVICE
    #[cfg(not(windows))]
    {
        matches!(e.raw_os_error(), Some(18))
    } // EXDEV
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
            // Cross-device fallback: copy into the final location,
            // then try to delete the source. The download is
            // *complete* the moment the copy succeeds — if the
            // remove fails (e.g. the upload server is still serving
            // a chunk from this .part on Windows, or the filesystem
            // is briefly read-only), we log it and leave the orphan
            // for the startup sweep to reap on next launch. Failing
            // the whole move here would mark a perfectly-good
            // completed download as Failed in the UI even though the
            // user's bytes are safely on disk.
            std::fs::copy(part_path, &final_path)?;
            if let Err(rm_err) = std::fs::remove_file(part_path) {
                tracing::warn!(
                    "Cross-device move: copied {} -> {} but failed to remove the source .part: {}. \
                     Orphan will be cleaned by the next startup sweep.",
                    part_path.display(),
                    final_path.display(),
                    rm_err,
                );
            }
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
pub(super) fn verify_hashset(
    file_hash: &[u8; 16],
    part_hashes: &[[u8; 16]],
    file_size: u64,
) -> bool {
    use md4::{Digest, Md4};
    if part_hashes.is_empty() {
        return false;
    }
    // The on-wire hashset is exactly one MD4 per ed2k part
    // (GetPartCount = ceil(file_size / PARTSIZE)). Reject any other count up
    // front: a correct hashset always has this many entries, so this only
    // rejects sets that would fail the MD4 check anyway, while stopping a peer
    // from padding the set to force extra allocation/hashing per connection.
    if part_hashes.len() != super::messages::ed2k_part_count_for_size(file_size) {
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
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| u32::from_be_bytes(v4.octets()))
            .unwrap_or(0),
    };
    // Read the request state under a short-lived guard and drop it before the
    // socket write. Holding the `CreditManager` read guard across
    // `write_packet_async().await` would block every `credit_manager.write()`
    // caller (and, since tokio's RwLock makes new readers queue behind a
    // pending writer, later readers too) for as long as the peer's socket is
    // backpressured. `handle_secident_signature` already scopes its guard the
    // same way.
    let Some(state) = ({
        let cm = cm.read().await;
        cm.secident_request_state(&peer_user_hash, peer_ip_u32, peer_secident_level)
    }) else {
        return Ok(None);
    };
    let challenge = rand::RngCore::next_u32(&mut rand::rngs::OsRng).wrapping_add(1);
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
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| u32::from_be_bytes(v4.octets()))
            .unwrap_or(0),
    };
    let (challenge_ip_kind, challenge_ip, add_trailer) = if (peer_secident_level & 1) != 0 {
        (None, 0u32, false)
    } else {
        // eMule: use REMOTECLIENT if we don't know our own public IP (LowID)
        if our_client_id == 0 || our_client_id < 0x0100_0000 {
            (
                Some(super::credits::CRYPT_CIP_REMOTECLIENT),
                peer_ip_u32,
                true,
            )
        } else {
            (
                Some(super::credits::CRYPT_CIP_LOCALCLIENT),
                our_client_id,
                true,
            )
        }
    };
    // Pull the public key and signature bytes out of the credit manager under a
    // short-lived read guard, then drop it BEFORE any socket write. Holding the
    // read guard across `write_packet_async().await` would stall all
    // `credit_manager.write()` callers (and later readers) for the duration of
    // a backpressured peer socket. Mirrors `handle_secident_signature`.
    let (pub_key, sig) = {
        let cm = cm.read().await;
        let pub_key = if state >= 2 {
            cm.our_public_key().to_vec()
        } else {
            Vec::new()
        };
        let sig = cm.create_signature_for_peer(
            &peer_user_hash,
            challenge,
            challenge_ip,
            challenge_ip_kind,
        );
        (pub_key, sig)
    };
    if state >= 2 && !pub_key.is_empty() {
        let mut key_pkt = Vec::with_capacity(1 + pub_key.len());
        key_pkt.push(pub_key.len() as u8);
        key_pkt.extend_from_slice(&pub_key);
        write_packet_async(writer, OP_EMULEPROT, OP_PUBLICKEY, &key_pkt).await?;
    }
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
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| u32::from_be_bytes(v4.octets()))
            .unwrap_or(0),
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
        let local_ip = if our_client_id >= 0x0100_0000 {
            our_client_id
        } else {
            0
        };
        cm.verify_signature(
            &peer_user_hash,
            challenge,
            challenge_kind,
            peer_ip_u32,
            local_ip,
            sig_bytes,
        )
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
                if proto == OP_EMULEPROT
                    && opcode == OP_AICHANSWER
                    && (38..=38 + crate::network::ed2k::aich::MAX_AICH_RECOVERY_BYTES)
                        .contains(&payload.len())
                {
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
    // Grow the buffer on the heap with bytes that actually arrive rather than
    // trusting the declared length up front. A peer that announces a near-10
    // MiB packet but then stalls can otherwise pin a full ~10 MiB allocation
    // per connection. We grow in bounded steps directly into the Vec instead
    // of via a large stack array: this read is awaited deep inside the
    // per-source download future, and a 64 KiB stack buffer there bloats that
    // (already huge) future's poll frame enough to overflow the worker stack
    // in debug builds.
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
    if protocol == OP_PACKEDPROT {
        let mut decoder = ZlibDecoder::new(&payload[..]);
        let mut unpacked = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = decoder.read(&mut buf).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("packed decode failed: {e}"),
                )
            })?;
            if n == 0 {
                break;
            }
            unpacked.extend_from_slice(&buf[..n]);
            if unpacked.len() > 10 * 1024 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "packed packet decompressed size exceeds limit",
                ));
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
    let pkt_len = u32::try_from(1 + payload.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "packet payload too large")
    })?;
    writer.write_u32_le(pkt_len).await?;
    writer.write_u8(opcode).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}
