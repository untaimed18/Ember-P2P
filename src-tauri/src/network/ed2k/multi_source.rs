use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::Context;
use flate2::read::{DeflateDecoder, ZlibDecoder};
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::sharing::manager::TransferControl;
use crate::types::Ed2kDownloadLimits;

use super::chunk_selection::ChunkSelector;
use super::comments::CommentManager;
use super::credits::CreditManager;
use super::part_tracker::PartTracker;
use super::sources::SourceManager;
use super::tcp_obfuscation::{self, Rc4Reader, Rc4Writer};
use super::transfer::{is_filtered_source_ip, DownloadEvent};

/// Shared registry of active download trackers so the shutdown path can
/// persist `.part.met` files even when download tasks are aborted.
pub type SharedTrackerRegistry = Arc<std::sync::Mutex<HashMap<String, Arc<RwLock<PartTracker>>>>>;

/// Maximum decompressed part size (PARTSIZE + margin = 10 MiB)
const MAX_DECOMPRESSED_PART: usize = 10 * 1024 * 1024;

/// eMule-style adaptive pipelining: keeps 1-3 request packets outstanding.
/// Module-level so the cross-part pipelining helpers below the per-source
/// download function can refer to it without re-declaring.
const MAX_BLOCKS_PER_REQUEST: usize = 3;

/// Persist a `.part.met` snapshot on the blocking pool without blocking
/// the caller. The caller MUST have already dropped any tracker
/// `RwLock` guard before invoking this — the previous design held
/// `tracker.read().await` across `atomic_write`, which serialized all
/// concurrent writers behind the fsync.
fn spawn_save_snapshot(snap: super::part_tracker::SaveSnapshot) {
    tokio::task::spawn_blocking(move || {
        if let Err(e) = snap.write_to_disk() {
            tracing::warn!("part.met save failed: {e}");
        }
    });
}

/// Maximum simultaneous source connections per download.
/// eMule typically has ~10 active connections per file.
const MAX_CONCURRENT_SOURCES: usize = 10;
const SOURCE_INJECTION_WAIT_SECS: u64 = 10;

/// A TCP stream + identity that has already been established by another
/// part of the system (typically the upload listener after recognising
/// an inbound KAD/server callback). Used to avoid the wasted-redial bug
/// where a LowID peer connects back to us via callback, we recognise
/// it, then throw away the inbound socket and try a fresh outbound to
/// a firewalled IP — which always fails with `stage:hello_wait:
/// forcibly closed`. By the time this struct is built the peer has
/// already exchanged Hello with us in `upload.rs`, so we know
/// `peer_user_hash`; `emule_info_done` records whether the EmuleInfo
/// round-trip was also completed (true for obfuscated callbacks,
/// where the obfuscation handshake also negotiates the eMule
/// extensions).
pub struct EstablishedStream {
    pub reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    pub writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    pub peer_user_hash: [u8; 16],
    pub emule_info_done: bool,
}

/// Pairing of an established peer stream with the synthesised
/// `DownloadSource` metadata the rest of the multi-source machinery
/// expects. Sent into a running `MultiSourceDownload` via
/// `new_established_rx` instead of `new_source_rx` so the worker takes
/// the "use this stream" path instead of the "dial this address" path.
pub struct EstablishedSource {
    pub source: DownloadSource,
    pub stream: EstablishedStream,
}

/// Target kernel TCP receive buffer for outbound peer sockets.
///
/// Windows' TCP auto-tuning ramps the receive window in stages and starts
/// from ~64 KiB, which is tight for high-bandwidth ED2K peers (at 10 MB/s
/// on a LAN-ish RTT a 64 KiB window caps us near 6 MB/s regardless of
/// what the peer is willing to ship). Pre-sizing to 1 MiB removes that
/// slow-ramp window without harming anything at low speeds — the kernel
/// only uses as much as the sender is actually filling, and `SockRef`'s
/// `set_recv_buffer_size` is advisory (the OS is free to clamp lower, it
/// just won't clamp higher-than-default). Mirrors the 256 KiB SO_SNDBUF
/// cap we apply to accepted upload sockets in `upload.rs`.
const PEER_RECV_BUFFER_BYTES: usize = 1024 * 1024;

/// Apply the standard low-latency + high-throughput socket tuning to a
/// freshly-connected outbound peer TCP stream: disable Nagle's algorithm
/// (OP_SENDINGPART packets are bursty, we don't want 40 ms per-batch
/// coalescing) and pre-size the receive buffer so the TCP window can grow
/// past Windows' stingy initial 64 KiB. Both are best-effort — `let _ =`
/// — because a failure here is never worth aborting a peer connection
/// over, and both are compatible with every ED2K peer we've ever seen
/// (they're strictly local socket-level knobs, invisible on the wire).
pub(crate) fn tune_peer_stream(stream: &tokio::net::TcpStream) {
    let _ = stream.set_nodelay(true);
    let sref = socket2::SockRef::from(stream);
    let _ = sref.set_recv_buffer_size(PEER_RECV_BUFFER_BYTES);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectionWaitAction {
    Continue,
    StartDeadline,
    Break,
}

fn injection_wait_action(
    pending_handles_empty: bool,
    injection_channel_open: bool,
    has_deadline: bool,
    deadline_elapsed: bool,
) -> InjectionWaitAction {
    if !pending_handles_empty {
        return InjectionWaitAction::Continue;
    }
    if !injection_channel_open || deadline_elapsed {
        return InjectionWaitAction::Break;
    }
    if !has_deadline {
        return InjectionWaitAction::StartDeadline;
    }
    InjectionWaitAction::Continue
}

/// RAII guard that clears `in_progress` flags on the part tracker when
/// dropped, preventing stuck parts if a source task exits via `?` or `bail!`.
struct InProgressGuard {
    tracker: Arc<RwLock<PartTracker>>,
    active: Vec<usize>,
}

impl InProgressGuard {
    fn new(tracker: Arc<RwLock<PartTracker>>) -> Self {
        Self { tracker, active: Vec::new() }
    }

    fn mark(&mut self, part_idx: usize) {
        if !self.active.contains(&part_idx) {
            self.active.push(part_idx);
        }
    }

    fn unmark(&mut self, part_idx: usize) {
        self.active.retain(|&p| p != part_idx);
    }
}

impl Drop for InProgressGuard {
    fn drop(&mut self) {
        if self.active.is_empty() {
            return;
        }
        let to_clear = std::mem::take(&mut self.active);
        let cleared = {
            if let Ok(mut t) = self.tracker.try_write() {
                for &p in &to_clear {
                    t.set_in_progress(p, false);
                }
                true
            } else {
                false
            }
        };
        if !cleared {
            let tracker = self.tracker.clone();
            tokio::spawn(async move {
                let mut t = tracker.write().await;
                for p in to_clear {
                    t.set_in_progress(p, false);
                }
            });
        }
    }
}

#[derive(Debug)]
struct PendingCompressedBlock {
    #[allow(dead_code)]
    compressed_total_size: u32,
    compressed: Vec<u8>,
}

/// A source that can provide parts of a file.
#[derive(Debug, Clone)]
pub struct DownloadSource {
    pub peer_ip: String,
    pub peer_port: u16,
    pub available_parts: Vec<bool>,
    /// Remote peer's user hash -- when set, outgoing TCP obfuscation is attempted.
    pub peer_user_hash: Option<[u8; 16]>,
    pub peer_connect_options: Option<u8>,
}

/// Coordinates downloading a single file from multiple sources.
/// Each source downloads different parts to maximize throughput.
pub struct MultiSourceDownload {
    pub transfer_id: String,
    pub file_hash: [u8; 16],
    pub file_name: String,
    pub file_size: u64,
    pub sources: Vec<DownloadSource>,
    pub download_dir: PathBuf,
    pub user_hash: [u8; 16],
    pub nickname: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub bandwidth_limiter: Arc<BandwidthLimiter>,
    pub control: Arc<TransferControl>,
    pub source_manager: Option<Arc<RwLock<SourceManager>>>,
    pub comment_manager: Option<Arc<RwLock<CommentManager>>>,
    pub credit_manager: Option<Arc<RwLock<CreditManager>>>,
    pub shared_buddy_info: Option<super::upload::SharedBuddyInfo>,
    pub obfuscation_enabled: bool,
    pub server_addr: Option<SocketAddr>,
    /// Channel for receiving new sources discovered during the download
    pub new_source_rx: Option<mpsc::Receiver<DownloadSource>>,
    /// Parallel injection channel for sources that arrive *with an
    /// already-handshaked TCP stream* — typically a LowID peer that
    /// reached us via KAD or server callback. Routed to the
    /// "skip connect+Hello, use this stream" code path in
    /// `download_parts_from_source`. Separate from `new_source_rx`
    /// because the payload type (carries a `Box<dyn AsyncRead/Write>`)
    /// is fundamentally different from the lightweight metadata
    /// `DownloadSource` and we don't want to perturb the dozens of
    /// existing send sites that operate on the metadata channel.
    /// Stays `None` for downloads that never receive a callback.
    pub new_established_rx: Option<mpsc::Receiver<EstablishedSource>>,
    pub ed2k_limits: Ed2kDownloadLimits,
    /// Our Ember identity hash, sent in EmuleInfo for friend identification
    pub ember_hash: [u8; 16],
    /// Live friend user-hash set for detecting friend connections
    pub friend_hashes: Option<Arc<RwLock<std::collections::HashSet<[u8; 16]>>>>,
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
    /// Shared pending AICH recovery retries
    pub aich_pending: Option<super::transfer::SharedAichPending>,
    /// GeoIP reader for country code lookups
    pub geoip: crate::geoip::GeoIpReader,
    /// Shared registry so the shutdown path can save our tracker
    pub tracker_registry: Option<SharedTrackerRegistry>,
    /// Lock-free counter the per-source workers bump on every
    /// peer-to-peer Source Exchange packet they send or receive.
    /// Drained on the network loop's stats tick into the
    /// `Source Exchange` overhead row.
    pub sx_overhead: crate::storage::statistics::SharedSxOverheadCounters,
}

async fn check_control(control: &TransferControl) -> anyhow::Result<()> {
    if control.is_cancelled() {
        anyhow::bail!("cancelled by user");
    }
    while control.is_paused() {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if control.is_cancelled() {
            anyhow::bail!("cancelled while paused");
        }
    }
    Ok(())
}

impl MultiSourceDownload {
    /// Run the multi-source download.
    pub async fn run(mut self, event_tx: mpsc::Sender<DownloadEvent>) -> anyhow::Result<()> {
        let max_dl = self.ed2k_limits.max_download_bytes;
        if self.file_size > max_dl {
            anyhow::bail!(
                "file size {} exceeds maximum allowed ({})",
                self.file_size,
                max_dl
            );
        }

        if self.file_size == 0 {
            if self.file_hash != super::hash::empty_ed2k_file_md4() {
                anyhow::bail!(
                    "zero-byte ed2k file requires file hash {}",
                    hex::encode(super::hash::empty_ed2k_file_md4())
                );
            }
            let _ = event_tx
                .send(DownloadEvent::SourcesUpdate {
                    transfer_id: self.transfer_id.clone(),
                    total: self.sources.len() as u32,
                    active: 0,
                    queued: 0,
                })
                .await;
            let _ = event_tx
                .send(DownloadEvent::Verifying {
                    transfer_id: self.transfer_id.clone(),
                })
                .await;
            super::transfer::finalize_zero_ed2k_file(
                &self.transfer_id,
                &self.file_name,
                self.file_hash,
                &self.download_dir,
            )
            .await?;
            let _ = event_tx
                .send(DownloadEvent::Progress {
                    transfer_id: self.transfer_id.clone(),
                    downloaded: 0,
                    total: 0,
                })
                .await;
            let _ = event_tx
                .send(DownloadEvent::Completed {
                    transfer_id: self.transfer_id.clone(),
                })
                .await;
            return Ok(());
        }

        if self.sources.is_empty() {
            anyhow::bail!("no sources available");
        }

        if self.control.is_cancelled() {
            anyhow::bail!("cancelled by user");
        }

        info!(
            "Starting multi-source download of {} from {} sources",
            hex::encode(self.file_hash),
            self.sources.len()
        );

        let temp_dir = self.download_dir.join("Temp");
        let completed_dir = self.download_dir.join("Downloads");
        tokio::fs::create_dir_all(&temp_dir).await?;
        tokio::fs::create_dir_all(&completed_dir).await?;

        let part_path = temp_dir.join(format!("{}.part", self.transfer_id));
        let mut pt = PartTracker::new(self.file_size, &part_path);
        pt.set_file_hash(self.file_hash);
        pt.set_file_name(&self.file_name);
        let tracker = Arc::new(RwLock::new(pt));

        if let Some(ref registry) = self.tracker_registry {
            if let Ok(mut reg) = registry.lock() {
                reg.insert(self.transfer_id.clone(), tracker.clone());
            }
        }

        // If .part.met shows progress but the .part file is missing, the tracker
        // is stale (e.g. user deleted the file manually).  Reset so we don't get
        // stuck in an infinite retry loop trying to open a nonexistent file.
        {
            let needs_reset = {
                let t = tracker.read().await;
                t.completed_bytes() > 0 && !part_path.exists()
            };
            if needs_reset {
                warn!(
                    "Part tracker shows progress but .part file is missing for {} — resetting",
                    self.transfer_id
                );
                let snap = {
                    let mut t = tracker.write().await;
                    *t = PartTracker::new_empty(self.file_size, &part_path);
                    t.set_file_hash(self.file_hash);
                    t.set_file_name(&self.file_name);
                    t.snapshot_for_save()
                };
                spawn_save_snapshot(snap);
            }
        }

        // Ensure the output file exists at the right length without truncating an existing
        // non-empty .part when .part.met reports 0 completed bytes (metadata load failure).
        {
            let completed_bytes = tracker.read().await.completed_bytes();
            let pp = part_path.clone();
            let fs = self.file_size;
            let tid = self.transfer_id.clone();
            tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                let existing_len = if pp.exists() {
                    std::fs::metadata(&pp)?.len()
                } else {
                    0
                };
                let resuming = completed_bytes > 0 || existing_len > 0;
                if resuming {
                    if completed_bytes == 0 && existing_len > 0 && existing_len != fs {
                        warn!(
                            "Preserving non-empty .part ({existing_len} bytes, expected {fs}) for {tid} while resume metadata shows no completed bytes — \
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
                } else {
                    let f = std::fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&pp)?;
                    if fs > 0 {
                        f.set_len(fs)?;
                    }
                }
                Ok(())
            })
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;
        }

        let _ = event_tx.send(DownloadEvent::PartFileReady {
            transfer_id: self.transfer_id.clone(),
            file_hash: self.file_hash,
            file_size: self.file_size,
            file_name: self.file_name.clone(),
        }).await;

        // Shared rarest-first chunk selector for dynamic part assignment
        let part_count = {
            let t = tracker.read().await;
            t.part_count
        };

        let chunk_selector = {
            let mut cs = ChunkSelector::new(part_count);
            cs.update_frequencies(&self.sources);
            Arc::new(RwLock::new(cs))
        };

        let queue_wait_secs = self.ed2k_limits.queue_wait_secs;

        // Pre-assign initial parts to each source using rarest-first.
        // eMule-style: when there are more sources than parts, allow multiple
        // sources to compete for the same part (first to finish wins).
        // Cap at MAX_SOURCES_PER_PART to avoid excessive connections.
        const MAX_SOURCES_PER_PART: usize = 5;
        let mut source_parts: Vec<Vec<usize>> = vec![Vec::new(); self.sources.len()];
        {
            let cs = chunk_selector.read().await;
            let mut assigned: Vec<bool> = vec![false; part_count];
            let mut part_source_count: Vec<usize> = vec![0; part_count];
            let mut active: Vec<usize> = Vec::new();

            {
                let t = tracker.read().await;
                let completed = t.completed_parts();
                for (p, &done) in completed.iter().enumerate() {
                    if done {
                        assigned[p] = true;
                    }
                }
            }

            let preview_prio = self.control.is_preview_priority();
            let (endgame_prefer_avail, gap_bytes, tracker_in_progress) = {
                let t = tracker.read().await;
                (t.remaining_count() <= 3 && part_count > 1, t.part_gap_bytes_vec(), t.in_progress.clone())
            };

            // First pass: unique part per source where possible (rarest-first)
            for src_idx in 0..self.sources.len() {
                let src = &self.sources[src_idx];
                let src_available: Vec<bool> = if src.available_parts.is_empty() {
                    vec![true; part_count]
                } else {
                    src.available_parts.clone()
                };

                if let Some(p) = cs.select_part(
                    &assigned,
                    &tracker_in_progress,
                    &src_available,
                    &active,
                    &gap_bytes,
                    preview_prio,
                    endgame_prefer_avail,
                ) {
                    source_parts[src_idx].push(p);
                    part_source_count[p] += 1;
                    assigned[p] = true;
                    active.push(p);
                }
            }

            // Second pass: sources that got no part compete for existing parts
            // (allows multiple sources to try the same part for small files).
            // Uses rarest-first selection with the MAX_SOURCES_PER_PART cap
            // enforced by marking over-subscribed parts as completed.
            for src_idx in 0..self.sources.len() {
                if !source_parts[src_idx].is_empty() {
                    continue;
                }
                let src = &self.sources[src_idx];
                let src_available: Vec<bool> = if src.available_parts.is_empty() {
                    vec![true; part_count]
                } else {
                    src.available_parts.clone()
                };

                let completed_parts = {
                    let t = tracker.read().await;
                    t.completed_parts().to_vec()
                };
                let mut excluded: Vec<bool> = completed_parts;
                for p in 0..part_count {
                    if part_source_count[p] >= MAX_SOURCES_PER_PART {
                        excluded[p] = true;
                    }
                }
                let no_in_progress = vec![false; part_count];
                if let Some(p) = cs.select_part(
                    &excluded,
                    &no_in_progress,
                    &src_available,
                    &active,
                    &gap_bytes,
                    preview_prio,
                    endgame_prefer_avail,
                ) {
                    source_parts[src_idx].push(p);
                    part_source_count[p] += 1;
                }
            }
        }

        // Shared part hashes for per-part verification (populated by first source)
        let part_hashes: Arc<RwLock<Vec<[u8; 16]>>> = Arc::new(RwLock::new(Vec::new()));
        // Trusted AICH master from HashSet2 (first peer to provide it wins).
        let shared_aich_master: Arc<RwLock<Option<[u8; 20]>>> = Arc::new(RwLock::new(None));

        // Source status counters (shared by all per-source tasks)
        let total_sources = Arc::new(AtomicU32::new(self.sources.len() as u32));
        let active_count = Arc::new(AtomicU32::new(0));
        let queued_count = Arc::new(AtomicU32::new(0));

        let _ = event_tx
            .send(DownloadEvent::SourcesUpdate {
                transfer_id: self.transfer_id.clone(),
                total: total_sources.load(Ordering::Relaxed),
                active: 0,
                queued: 0,
            })
            .await;

        // Progress aggregator channel: i64 signals used as a trigger
        // (value ignored); actual progress is read from the tracker to
        // avoid double-counting overlapping sources. Capacity 4096 (was
        // 256): with up to MAX_CONCURRENT_SOURCES sources each pushing a
        // signal per ~180 KiB block, 256 was easily filled while the
        // aggregator was waiting on `event_tx_clone.send().await`,
        // back-pressuring every source coroutine.
        let (progress_tx, mut progress_rx) = mpsc::channel::<(usize, i64)>(4096);
        let transfer_id = self.transfer_id.clone();
        let file_size = self.file_size;
        let event_tx_clone = event_tx.clone();
        let agg_active = active_count.clone();
        let agg_queued = queued_count.clone();
        let agg_total = total_sources.clone();
        let agg_tracker = tracker.clone();

        // Coalesce Progress / SourcesUpdate emissions to a fixed cadence
        // (~200 ms). The previous design fired one `transfer-progress`
        // Tauri event per received block, which saturated the webview
        // main thread with up to thousands of events/sec on a healthy
        // swarm. The DB persist side is already throttled, so the only
        // consumer that benefits from sub-second granularity is the UI,
        // and 200 ms is well below human flicker perception.
        let aggregator = tokio::spawn(async move {
            const EMIT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);
            let mut last_active: u32 = 0;
            let mut last_queued: u32 = 0;
            let mut last_total: u32 = agg_total.load(Ordering::Relaxed);
            let mut pending_progress = false;
            let mut last_emitted_bytes: u64 = 0;
            let mut interval = tokio::time::interval(EMIT_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Skip the immediate first tick so we don't emit before any
            // data arrives.
            interval.tick().await;

            loop {
                tokio::select! {
                    sig = progress_rx.recv() => {
                        match sig {
                            Some(_) => { pending_progress = true; }
                            None => break,
                        }
                    }
                    _ = interval.tick() => {
                        let cur_active = agg_active.load(Ordering::Relaxed);
                        let cur_queued = agg_queued.load(Ordering::Relaxed);
                        let cur_total = agg_total.load(Ordering::Relaxed);
                        let sources_changed = cur_active != last_active
                            || cur_queued != last_queued
                            || cur_total != last_total;

                        if pending_progress || sources_changed {
                            let capped = {
                                let t = agg_tracker.read().await;
                                t.completed_bytes().min(file_size)
                            };
                            // Skip the Progress emit when nothing actually
                            // changed (e.g. only `pending_progress` from a
                            // negative correction that landed at the same
                            // total). Saves a UI round-trip when sources
                            // are flapping but bytes are static.
                            if pending_progress && capped != last_emitted_bytes {
                                let _ = event_tx_clone
                                    .send(DownloadEvent::Progress {
                                        transfer_id: transfer_id.clone(),
                                        downloaded: capped,
                                        total: file_size,
                                    })
                                    .await;
                                last_emitted_bytes = capped;
                            }
                            pending_progress = false;

                            if sources_changed {
                                last_active = cur_active;
                                last_queued = cur_queued;
                                last_total = cur_total;
                                let _ = event_tx_clone
                                    .send(DownloadEvent::SourcesUpdate {
                                        transfer_id: transfer_id.clone(),
                                        total: cur_total,
                                        active: cur_active,
                                        queued: cur_queued,
                                    })
                                    .await;
                            }
                        }
                    }
                }
            }
            // Final flush so the UI sees the final byte count when the
            // last source closes.
            let capped = {
                let t = agg_tracker.read().await;
                t.completed_bytes().min(file_size)
            };
            if capped != last_emitted_bytes {
                let _ = event_tx_clone
                    .send(DownloadEvent::Progress {
                        transfer_id: transfer_id.clone(),
                        downloaded: capped,
                        total: file_size,
                    })
                    .await;
            }
        });

        // Semaphore to limit concurrent source connections (avoids overwhelming
        // the network with dozens of simultaneous TCP handshakes to unreachable peers)
        let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SOURCES));

        // Per-file writer with its own dedicated thread. Replaces the
        // previous `Arc<Mutex<File>>` pattern that serialized all writers
        // on a single OS-mutex and burned a `spawn_blocking` slot per
        // 180 KiB block. See `network::ed2k::write_coordinator`.
        let shared_part_file = super::write_coordinator::PartFileWriter::open(
            part_path.clone(),
            super::write_coordinator::OpenMode::OpenExisting,
        )
        .await
        .map_err(|e| anyhow::anyhow!("open part file: {e}"))?;

        // Spawn per-source download tasks
        let mut handles = Vec::new();
        for (src_idx, parts) in source_parts.into_iter().enumerate() {
            if parts.is_empty() {
                continue;
            }
            let source = self.sources[src_idx].clone();
            let tracker = tracker.clone();
            let part_path = part_path.clone();
            let file_hash = self.file_hash;
            let file_size = self.file_size;
            let user_hash = self.user_hash;
            let nickname = self.nickname.clone();
            let tcp_port = self.tcp_port;
            let udp_port = self.udp_port;
            let bw = self.bandwidth_limiter.clone();
            let progress_tx = progress_tx.clone();
            let ph = part_hashes.clone();
            let aich_m = shared_aich_master.clone();
            let src_active = active_count.clone();
            let src_queued = queued_count.clone();
            let sm_clone = self.source_manager.clone();
            let cm_clone = self.credit_manager.clone();
            let cmt_clone = self.comment_manager.clone();
            let cs_clone = chunk_selector.clone();
            let src_avail = self.sources[src_idx].available_parts.clone();
            let etx_clone = event_tx.clone();
            let tid_clone = self.transfer_id.clone();
            let bi_clone = self.shared_buddy_info.clone();
            let ctrl_clone = self.control.clone();
                let obf_enabled = self.obfuscation_enabled;
                let hello_server = self.server_addr;
                let src_ember_hash = self.ember_hash;
                let nick_for_src = self.nickname.clone();
            let sem_clone = conn_semaphore.clone();
            let qw = queue_wait_secs;
            let shared_out = shared_part_file.clone();
            let epx_payload = self.ember_payload.clone();
            let epx_gen = self.ember_payload_generation.clone();
            let aich_p = self.aich_pending.clone();
            let sx_ipf = self.ip_filter.clone();
            let sx_ban = self.banned_ips.clone();
            let sx_ext = self.external_ip;
            let geo_clone = self.geoip.clone();
            let fh_clone = self.friend_hashes.clone();
            let sx_oh = self.sx_overhead.clone();

            let fail_etx = event_tx.clone();
            let fail_tid = self.transfer_id.clone();
            let fail_ip = source.peer_ip.clone();
            let fail_port = source.peer_port;
            let handle = tokio::spawn(async move {
                if sem_clone.available_permits() == 0 {
                    let _ = fail_etx.send(DownloadEvent::SourceDetail {
                        transfer_id: fail_tid.clone(),
                        ip: fail_ip.clone(),
                        port: fail_port,
                        status: "too_many_conns".to_string(),
                        queue_rank: None,
                        speed: 0,
                        transferred: 0,
                        client_software: String::new(),
                        peer_name: String::new(),
                        failure_kind: None,
                        available_parts: None,
                        total_parts: None,
                        country_code: None,
                    }).await;
                }
                let _permit = match sem_clone.acquire().await {
                    Ok(p) => p,
                    Err(_) => return (src_idx, parts, Err(anyhow::anyhow!("download cancelled"))),
                };
                let freq_avail = src_avail.clone();
                let result = download_parts_from_source(
                    src_idx,
                    &source,
                    &parts,
                    tracker,
                    &part_path,
                    &file_hash,
                    file_size,
                    &user_hash,
                    &nickname,
                    tcp_port,
                    udp_port,
                    bw,
                    progress_tx,
                    ph,
                    aich_m,
                    src_active.clone(),
                    src_queued.clone(),
                    sm_clone,
                    cm_clone,
                    cmt_clone,
                    Some(cs_clone.clone()),
                    src_avail,
                    Some(etx_clone),
                    tid_clone,
                    bi_clone,
                    ctrl_clone,
                    obf_enabled,
                    hello_server,
                    qw,
                    Some(shared_out),
                    epx_payload.clone(),
                    epx_gen.clone(),
                    aich_p,
                    sx_ipf,
                    sx_ban,
                    sx_ext,
                    geo_clone.clone(),
                    fh_clone.clone(),
                    src_ember_hash,
                    nick_for_src.clone(),
                    sx_oh.clone(),
                    // No pre-established stream — this is the initial-
                    // sources path; we always dial these peers fresh.
                    None,
                )
                .await;

                if !freq_avail.is_empty() {
                    let mut cs = cs_clone.write().await;
                    cs.remove_source(&freq_avail);
                }

                if let Err(e) = &result {
                    if !super::transfer::is_queue_detached_error(&e.to_string()) {
                        warn!("Source {} ({}) failed: {e:#}", src_idx, fail_ip);
                        let _ = fail_etx.send(DownloadEvent::SourceDetail {
                            transfer_id: fail_tid,
                            ip: fail_ip,
                            port: fail_port,
                            status: "failed".to_string(),
                            queue_rank: None,
                            speed: 0,
                            transferred: 0,
                            client_software: String::new(),
                            peer_name: String::new(),
                            failure_kind: Some(super::transfer::classify_error(&e.to_string())),
                            available_parts: None,
                            total_parts: None,
                            country_code: None,
                        }).await;
                    }
                }
                (src_idx, parts, result)
            });
            handles.push(handle);
        }

        // Wait for all initial sources and accept new sources as they arrive
        let mut next_src_idx = self.sources.len();
        let mut injected_sources: Vec<DownloadSource> = Vec::new();

        if let Some(mut new_source_rx) = self.new_source_rx.take() {
            // Established-stream injection channel — populated by the
            // KAD/server callback path in `network/mod.rs` when a
            // LowID peer connects back to our upload listener for a
            // file we're already downloading. Stays None (no-op) when
            // no callback ever arrives for this transfer; the
            // `std::future::pending()` sentinel below makes the
            // select! arm uncostly when the channel doesn't exist.
            let mut new_established_rx = self.new_established_rx.take();
            let abort_handles: Vec<tokio::task::AbortHandle> = handles.iter().map(|h| h.abort_handle()).collect();
            let mut pending_futs: FuturesUnordered<tokio::task::JoinHandle<(usize, Vec<usize>, anyhow::Result<()>)>> = handles.into_iter().collect();
            let mut injected_abort_handles: Vec<tokio::task::AbortHandle> = Vec::new();
            // Concurrent loop: wait for handles to complete while accepting new sources.
            // When all initial sources finish but parts remain, keep listening for
            // injected sources (from ongoing KAD/server discovery) for up to 60 seconds
            // before falling through to retry rounds.
            let mut injection_deadline: Option<tokio::time::Instant> = None;
            let mut injection_channel_open = true;
            loop {
                let all_done = {
                    let t = tracker.read().await;
                    t.all_complete()
                };
                if all_done {
                    break;
                }
                let deadline_elapsed = injection_deadline
                    .map(|deadline| tokio::time::Instant::now() >= deadline)
                    .unwrap_or(false);
                match injection_wait_action(
                    pending_futs.is_empty(),
                    injection_channel_open,
                    injection_deadline.is_some(),
                    deadline_elapsed,
                ) {
                    InjectionWaitAction::StartDeadline => {
                        info!("All source tasks done, waiting up to {}s for new sources via injection", SOURCE_INJECTION_WAIT_SECS);
                        injection_deadline = Some(
                            tokio::time::Instant::now()
                                + std::time::Duration::from_secs(SOURCE_INJECTION_WAIT_SECS),
                        );
                    }
                    InjectionWaitAction::Break => {
                        if !injection_channel_open {
                            info!("All source tasks done and source injection channel is closed; proceeding to retry rounds");
                        } else {
                            info!("Source injection deadline reached, proceeding to retry rounds");
                        }
                        break;
                    }
                    InjectionWaitAction::Continue => {}
                }

                tokio::select! {
                    result = async {
                        if pending_futs.is_empty() {
                            // Idle pacing: was 2s, now 250ms. The
                            // `select!` already wakes immediately when a
                            // new source is injected via `new_source_rx`,
                            // so this only matters when *no* source
                            // arrives — and 250ms is responsive enough
                            // for the periodic re-check of completion /
                            // outer state without burning CPU.
                            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                            None
                        } else {
                            pending_futs.next().await
                        }
                    } => {
                        let _ = result;
                    }
                    // Accept new source from the injection channel
                    new_src = new_source_rx.recv() => {
                        if let Some(source) = new_src {
                            injection_deadline = None;

                            // Compute parts FIRST, before incrementing
                            // counters / emitting `SourcesUpdate` /
                            // touching `chunk_selector.total_sources`.
                            // Previously we bumped `total_sources` and
                            // emitted the event before the `parts.is_empty()`
                            // check below — when no part could be assigned
                            // (chunk selector returns None: every part
                            // already in_progress / done), the `continue`
                            // left the counter and UI total inflated for
                            // the lifetime of the download. Compute first,
                            // commit only on success.
                            let parts = {
                                let cs = chunk_selector.read().await;
                                let t = tracker.read().await;
                                let completed = t.completed_parts().to_vec();
                                let in_prog = t.in_progress.clone();
                                let endgame_prefer =
                                    t.remaining_count() <= 3 && t.part_count > 1;
                                let gap_bytes = t.part_gap_bytes_vec();
                                let avail = if source.available_parts.is_empty() {
                                    vec![true; t.part_count]
                                } else {
                                    source.available_parts.clone()
                                };
                                let pp = self.control.is_preview_priority();
                                let active: Vec<usize> = in_prog.iter().enumerate()
                                    .filter(|(_, &ip)| ip).map(|(i, _)| i).collect();
                                if let Some(p) = cs.select_part(
                                    &completed,
                                    &in_prog,
                                    &avail,
                                    &active,
                                    &gap_bytes,
                                    pp,
                                    endgame_prefer,
                                ) {
                                    vec![p]
                                } else {
                                    Vec::new()
                                }
                            };
                            if parts.is_empty() {
                                // Source not usable right now (e.g. all
                                // parts already in progress); drop it
                                // silently so we don't pollute counters
                                // or UI totals. The peer can be
                                // re-injected via KAD/server SX if it
                                // becomes useful later.
                                continue;
                            }

                            // Commit: assign an idx, bump counters, emit
                            // `SourcesUpdate`, and update the chunk
                            // selector — only now that we know the
                            // source will actually start a worker task.
                            let src_idx = next_src_idx;
                            next_src_idx += 1;
                            let new_total = total_sources.fetch_add(1, Ordering::Relaxed) + 1;
                            let _ = event_tx
                                .send(DownloadEvent::SourcesUpdate {
                                    transfer_id: self.transfer_id.clone(),
                                    total: new_total,
                                    active: active_count.load(Ordering::Relaxed),
                                    queued: queued_count.load(Ordering::Relaxed),
                                })
                                .await;
                            if !source.available_parts.is_empty() {
                                let mut cs = chunk_selector.write().await;
                                for (i, &has) in source.available_parts.iter().enumerate() {
                                    if i < cs.part_frequency.len() && has {
                                        cs.part_frequency[i] = cs.part_frequency[i].saturating_add(1);
                                    }
                                }
                                cs.total_sources = cs.total_sources.saturating_add(1);
                            }
                            info!("Injecting new source {}:{} (idx {src_idx}) into active download", source.peer_ip, source.peer_port);
                            injected_sources.push(source.clone());
                            let src = source.clone();
                            let trk = tracker.clone();
                            let pp = part_path.clone();
                            let fh = self.file_hash;
                            let fs = self.file_size;
                            let uh = self.user_hash;
                            let nn = self.nickname.clone();
                            let tp = self.tcp_port;
                            let up = self.udp_port;
                            let bw = self.bandwidth_limiter.clone();
                            let _ptx = event_tx.clone();
                            let ph = part_hashes.clone();
                            let aich_m = shared_aich_master.clone();
                            let sa = active_count.clone();
                            let sq = queued_count.clone();
                            let sm = self.source_manager.clone();
                            let cm = self.credit_manager.clone();
                            let cmt = self.comment_manager.clone();
                            let cs = chunk_selector.clone();
                            let avail = source.available_parts.clone();
                            let etx = event_tx.clone();
                            let tid = self.transfer_id.clone();
                            let bi = self.shared_buddy_info.clone();
                            let ctrl = self.control.clone();
                            let sem = conn_semaphore.clone();

                            let fail_etx = event_tx.clone();
                            let fail_tid = self.transfer_id.clone();
                            let fail_ip = source.peer_ip.clone();
                            let fail_port = source.peer_port;

                            let inj_progress_tx = progress_tx.clone();
                            let obf_enabled = self.obfuscation_enabled;
                            let hello_server = self.server_addr;
                            let inj_ember_hash = self.ember_hash;
                            let inj_nick = self.nickname.clone();
                            let inj_qw = queue_wait_secs;
                            let inj_shared_out = shared_part_file.clone();
                            let inj_epx = self.ember_payload.clone();
                            let inj_epx_gen = self.ember_payload_generation.clone();
                            let inj_aich_p = self.aich_pending.clone();
                            let inj_ipf = self.ip_filter.clone();
                            let inj_ban = self.banned_ips.clone();
                            let inj_ext = self.external_ip;
                            let inj_geo = self.geoip.clone();
                            let inj_fh = self.friend_hashes.clone();
                            let inj_sx_oh = self.sx_overhead.clone();
                            let handle = tokio::spawn(async move {
                                let _permit = match sem.acquire().await {
                                    Ok(p) => p,
                                    Err(_) => return (src_idx, Vec::new(), Err(anyhow::anyhow!("download cancelled"))),
                                };
                                let freq_avail = avail.clone();
                                let result = download_parts_from_source(
                                    src_idx, &src, &parts, trk, &pp, &fh, fs, &uh, &nn,
                                    tp, up, bw, inj_progress_tx, ph, aich_m, sa, sq, sm, cm,
                                    cmt, Some(cs.clone()), avail, Some(etx), tid, bi, ctrl,
                                    obf_enabled, hello_server, inj_qw,
                                    Some(inj_shared_out), inj_epx, inj_epx_gen,
                                    inj_aich_p,
                                    inj_ipf, inj_ban, inj_ext,
                                    inj_geo, inj_fh,
                                    inj_ember_hash,
                                    inj_nick,
                                    inj_sx_oh,
                                    // Metadata-only injection (peer
                                    // discovered via KAD/server source
                                    // exchange); no pre-handshaked
                                    // stream available.
                                    None,
                                ).await;
                                if !freq_avail.is_empty() {
                                    let mut csel = cs.write().await;
                                    csel.remove_source(&freq_avail);
                                }
                                if let Err(e) = &result {
                                    if !super::transfer::is_queue_detached_error(&e.to_string()) {
                                        warn!("Injected source {} ({}) failed: {e:#}", src_idx, fail_ip);
                                        let _ = fail_etx.send(DownloadEvent::SourceDetail {
                                            transfer_id: fail_tid,
                                            ip: fail_ip,
                                            port: fail_port,
                                            status: "failed".to_string(),
                                            queue_rank: None,
                                            speed: 0,
                                            transferred: 0,
                                            client_software: String::new(),
                                            peer_name: String::new(),
                                            failure_kind: Some(super::transfer::classify_error(&e.to_string())),
                                            available_parts: None,
                                            total_parts: None,
                                            country_code: None,
                                        }).await;
                                    }
                                }
                                (src_idx, parts, result)
                            });
                            injected_abort_handles.push(handle.abort_handle());
                            pending_futs.push(handle);
                        } else {
                            injection_channel_open = false;
                            if pending_futs.is_empty() {
                                info!("Source injection channel closed with no active source tasks left; proceeding to retry rounds");
                                break;
                            }
                        }
                    }
                    // Accept a pre-handshaked stream from the
                    // established-source channel. Same wiring as the
                    // metadata path above except we pass the supplied
                    // reader/writer/peer_user_hash through as
                    // `pre_established` so `download_parts_from_source`
                    // skips its own connect+Hello+EmuleInfo dance.
                    // Without this branch, when a LowID peer reaches
                    // us via KAD callback for a file we're already
                    // downloading, network/mod.rs would otherwise just
                    // metadata-inject the peer into `new_source_rx`,
                    // which then triggers a fresh outbound connect that
                    // can't reach a LowID peer behind NAT — every such
                    // injection failed with `stage:hello_wait: forcibly
                    // closed` before this fix.
                    new_est = async {
                        match &mut new_established_rx {
                            Some(rx) => rx.recv().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        if let Some(es) = new_est {
                            injection_deadline = None;

                            let source = es.source;
                            let stream = es.stream;

                            // Compute parts BEFORE bumping counters /
                            // emitting events / mutating the chunk
                            // selector — same reasoning as the
                            // metadata-injection arm above. If no
                            // part can be assigned, the live stream
                            // is dropped (nothing else to do with it
                            // — only one task can read each TCP
                            // socket) but we don't pollute counters /
                            // UI totals. Without this ordering, an
                            // unusable callback inflates `total_sources`
                            // and the UI's source count permanently.
                            let parts = {
                                let cs = chunk_selector.read().await;
                                let t = tracker.read().await;
                                let completed = t.completed_parts().to_vec();
                                let in_prog = t.in_progress.clone();
                                let endgame_prefer =
                                    t.remaining_count() <= 3 && t.part_count > 1;
                                let gap_bytes = t.part_gap_bytes_vec();
                                let avail = if source.available_parts.is_empty() {
                                    vec![true; t.part_count]
                                } else {
                                    source.available_parts.clone()
                                };
                                let pp = self.control.is_preview_priority();
                                let active: Vec<usize> = in_prog.iter().enumerate()
                                    .filter(|(_, &ip)| ip).map(|(i, _)| i).collect();
                                if let Some(p) = cs.select_part(
                                    &completed,
                                    &in_prog,
                                    &avail,
                                    &active,
                                    &gap_bytes,
                                    pp,
                                    endgame_prefer,
                                ) {
                                    vec![p]
                                } else {
                                    Vec::new()
                                }
                            };
                            if parts.is_empty() {
                                debug!(
                                    "Pre-established source {}:{} has no assignable parts; dropping stream",
                                    source.peer_ip, source.peer_port,
                                );
                                drop(stream);
                                continue;
                            }

                            // Commit phase: only now that we know the
                            // worker will actually run, bump counters
                            // and update the chunk selector.
                            let src_idx = next_src_idx;
                            next_src_idx += 1;
                            let new_total = total_sources.fetch_add(1, Ordering::Relaxed) + 1;
                            let _ = event_tx
                                .send(DownloadEvent::SourcesUpdate {
                                    transfer_id: self.transfer_id.clone(),
                                    total: new_total,
                                    active: active_count.load(Ordering::Relaxed),
                                    queued: queued_count.load(Ordering::Relaxed),
                                })
                                .await;
                            if !source.available_parts.is_empty() {
                                let mut cs = chunk_selector.write().await;
                                for (i, &has) in source.available_parts.iter().enumerate() {
                                    if i < cs.part_frequency.len() && has {
                                        cs.part_frequency[i] = cs.part_frequency[i].saturating_add(1);
                                    }
                                }
                                cs.total_sources = cs.total_sources.saturating_add(1);
                            }
                            info!(
                                "Injecting pre-established source {}:{} (idx {src_idx}) into active download",
                                source.peer_ip, source.peer_port,
                            );
                            injected_sources.push(source.clone());
                            let src = source.clone();
                            let trk = tracker.clone();
                            let pp = part_path.clone();
                            let fh = self.file_hash;
                            let fs = self.file_size;
                            let uh = self.user_hash;
                            let nn = self.nickname.clone();
                            let tp = self.tcp_port;
                            let up = self.udp_port;
                            let bw = self.bandwidth_limiter.clone();
                            let _ptx = event_tx.clone();
                            let ph = part_hashes.clone();
                            let aich_m = shared_aich_master.clone();
                            let sa = active_count.clone();
                            let sq = queued_count.clone();
                            let sm = self.source_manager.clone();
                            let cm = self.credit_manager.clone();
                            let cmt = self.comment_manager.clone();
                            let cs = chunk_selector.clone();
                            let avail = source.available_parts.clone();
                            let etx = event_tx.clone();
                            let tid = self.transfer_id.clone();
                            let bi = self.shared_buddy_info.clone();
                            let ctrl = self.control.clone();
                            let sem = conn_semaphore.clone();

                            let fail_etx = event_tx.clone();
                            let fail_tid = self.transfer_id.clone();
                            let fail_ip = source.peer_ip.clone();
                            let fail_port = source.peer_port;

                            let inj_progress_tx = progress_tx.clone();
                            let obf_enabled = self.obfuscation_enabled;
                            let hello_server = self.server_addr;
                            let inj_ember_hash = self.ember_hash;
                            let inj_nick = self.nickname.clone();
                            let inj_qw = queue_wait_secs;
                            let inj_shared_out = shared_part_file.clone();
                            let inj_epx = self.ember_payload.clone();
                            let inj_epx_gen = self.ember_payload_generation.clone();
                            let inj_aich_p = self.aich_pending.clone();
                            let inj_ipf = self.ip_filter.clone();
                            let inj_ban = self.banned_ips.clone();
                            let inj_ext = self.external_ip;
                            let inj_geo = self.geoip.clone();
                            let inj_fh = self.friend_hashes.clone();
                            let inj_sx_oh = self.sx_overhead.clone();
                            let handle = tokio::spawn(async move {
                                let _permit = match sem.acquire().await {
                                    Ok(p) => p,
                                    Err(_) => return (src_idx, Vec::new(), Err(anyhow::anyhow!("download cancelled"))),
                                };
                                let freq_avail = avail.clone();
                                let result = download_parts_from_source(
                                    src_idx, &src, &parts, trk, &pp, &fh, fs, &uh, &nn,
                                    tp, up, bw, inj_progress_tx, ph, aich_m, sa, sq, sm, cm,
                                    cmt, Some(cs.clone()), avail, Some(etx), tid, bi, ctrl,
                                    obf_enabled, hello_server, inj_qw,
                                    Some(inj_shared_out), inj_epx, inj_epx_gen,
                                    inj_aich_p,
                                    inj_ipf, inj_ban, inj_ext,
                                    inj_geo, inj_fh,
                                    inj_ember_hash,
                                    inj_nick,
                                    inj_sx_oh,
                                    // The crucial bit: hand the
                                    // already-handshaked stream to
                                    // download_parts_from_source so it
                                    // takes the adoption branch instead
                                    // of dialing the LowID peer back.
                                    Some(stream),
                                ).await;
                                if !freq_avail.is_empty() {
                                    let mut csel = cs.write().await;
                                    csel.remove_source(&freq_avail);
                                }
                                if let Err(e) = &result {
                                    if !super::transfer::is_queue_detached_error(&e.to_string()) {
                                        warn!("Pre-established source {} ({}) failed: {e:#}", src_idx, fail_ip);
                                        let _ = fail_etx.send(DownloadEvent::SourceDetail {
                                            transfer_id: fail_tid,
                                            ip: fail_ip,
                                            port: fail_port,
                                            status: "failed".to_string(),
                                            queue_rank: None,
                                            speed: 0,
                                            transferred: 0,
                                            client_software: String::new(),
                                            peer_name: String::new(),
                                            failure_kind: Some(super::transfer::classify_error(&e.to_string())),
                                            available_parts: None,
                                            total_parts: None,
                                            country_code: None,
                                        }).await;
                                    }
                                }
                                (src_idx, parts, result)
                            });
                            injected_abort_handles.push(handle.abort_handle());
                            pending_futs.push(handle);
                        } else {
                            // Established channel closed — drop our
                            // handle to it so future select iterations
                            // skip the recv branch entirely (via the
                            // `std::future::pending` sentinel).
                            new_established_rx = None;
                        }
                    }
                }
            }
            // Drain remaining handles
            let all_parts_done = {
                let t = tracker.read().await;
                t.all_complete()
            };
            if all_parts_done {
                for ah in &abort_handles { ah.abort(); }
                for ah in &injected_abort_handles { ah.abort(); }
            }
            while let Some(_) = pending_futs.next().await {}
        } else {
            let all_parts_done = {
                let t = tracker.read().await;
                t.all_complete()
            };
            if all_parts_done {
                for handle in handles {
                    handle.abort();
                    let _ = handle.await;
                }
            } else {
                for handle in handles {
                    if let Ok((_src_idx, _parts, result)) = handle.await {
                        if result.is_err() {
                            // Parts from failed sources remain incomplete in tracker
                        }
                    }
                }
            }
        }

        // Drop our copy of progress_tx so the aggregator can finish once all
        // initial and injected source tasks are done.
        drop(progress_tx);

        aggregator.await?;

        // Emit final source counts after all tasks complete
        let _ = event_tx
            .send(DownloadEvent::SourcesUpdate {
                transfer_id: self.transfer_id.clone(),
                total: total_sources.load(Ordering::Relaxed),
                active: active_count.load(Ordering::Relaxed),
                queued: queued_count.load(Ordering::Relaxed),
            })
            .await;

        // Retry incomplete parts (from failed sources or hash mismatches).
        //
        // Two backoff knobs prevent the previously-observed retry storm
        // where a single dead source (failing instantly at hello_wait)
        // would burn through all 3 retry rounds in ~1.3 seconds and get
        // us soft-banned by the remote eMule client for re-asking faster
        // than `FILEREASKTIME`:
        //   * `RETRY_ROUND_MIN_INTERVAL_SECS`: minimum wall-clock gap
        //     between consecutive retry rounds. If a round drains in
        //     less than this (because every source rejected us
        //     immediately), we sleep the remainder before the next round.
        //   * `SOURCE_RETRY_COOLDOWN_SECS`: minimum gap between two
        //     dial attempts to the same `(ip, port)`. Skips a source
        //     that we (or the initial spawn loop) just tried, regardless
        //     of which round we're in.
        // Rounds where every candidate source is on cooldown DO NOT
        // consume the retry budget — we sleep until the soonest cooldown
        // expires and re-evaluate. This keeps the retry budget available
        // for genuinely fresh attempts.
        const RETRY_ROUND_MIN_INTERVAL_SECS: u64 = 30;
        const SOURCE_RETRY_COOLDOWN_SECS: u64 = 60;
        let retry_round_min_interval =
            std::time::Duration::from_secs(RETRY_ROUND_MIN_INTERVAL_SECS);
        let source_retry_cooldown =
            std::time::Duration::from_secs(SOURCE_RETRY_COOLDOWN_SECS);

        let max_retry_rounds = self.ed2k_limits.multisource_retry_rounds;
        // Initial source attempts have just completed (or just failed);
        // seed the cooldown table with `now()` so round 1 doesn't
        // immediately re-dial the same peers we tried in the initial
        // pass. Same-peer retries from this round onward will require
        // SOURCE_RETRY_COOLDOWN_SECS to elapse first.
        let mut source_dial_history: HashMap<(String, u16), std::time::Instant> =
            HashMap::new();
        {
            let now = std::time::Instant::now();
            for s in self.sources.iter().chain(injected_sources.iter()) {
                source_dial_history.insert((s.peer_ip.clone(), s.peer_port), now);
            }
        }
        let mut last_round_end: Option<std::time::Instant> = None;
        let mut retry_round: u32 = 0;
        while retry_round < max_retry_rounds {
            check_control(&self.control).await?;

            let incomplete: Vec<usize> = {
                let t = tracker.read().await;
                (0..t.part_count)
                    .filter(|&i| !t.is_part_complete(i))
                    .collect()
            };
            if incomplete.is_empty() {
                break;
            }

            // Inter-round backoff: never start a retry round less than
            // `retry_round_min_interval` after the previous one ended.
            // Without this, a peer that fails at hello in 200 ms gets
            // re-dialled three times in under a second.
            if let Some(end) = last_round_end {
                let elapsed = end.elapsed();
                if elapsed < retry_round_min_interval {
                    let wait = retry_round_min_interval - elapsed;
                    info!(
                        "Retry round {}/{}: previous round ended {:.1}s ago, sleeping {:.1}s before next attempt",
                        retry_round + 1,
                        max_retry_rounds,
                        elapsed.as_secs_f64(),
                        wait.as_secs_f64(),
                    );
                    tokio::time::sleep(wait).await;
                    check_control(&self.control).await?;
                }
            }

            let all_sources: Vec<DownloadSource> = self.sources.iter()
                .chain(injected_sources.iter())
                .cloned()
                .collect();
            // Build the cooldown-eligible candidate list once; re-used
            // by every part assignment below.
            let now = std::time::Instant::now();
            let eligible: Vec<bool> = all_sources
                .iter()
                .map(|s| match source_dial_history.get(&(s.peer_ip.clone(), s.peer_port)) {
                    Some(t) => now.duration_since(*t) >= source_retry_cooldown,
                    None => true,
                })
                .collect();

            let mut retry_assignments: Vec<Vec<usize>> = vec![Vec::new(); all_sources.len()];
            let mut next_source_cursor = 0usize;
            // Sort by ascending rarity so the rarest parts get assigned first
            let mut sorted_incomplete = incomplete.clone();
            {
                let cs = chunk_selector.read().await;
                sorted_incomplete.sort_by_key(|&p| {
                    cs.part_frequency.get(p).copied().unwrap_or(u16::MAX)
                });
            }
            for &part_idx in &sorted_incomplete {
                let mut candidates = Vec::new();
                for (src_idx, source) in all_sources.iter().enumerate() {
                    if !eligible[src_idx] {
                        continue;
                    }
                    if source.available_parts.is_empty()
                        || source.available_parts.get(part_idx).copied().unwrap_or(false)
                    {
                        candidates.push(src_idx);
                    }
                }
                if candidates.is_empty() {
                    continue;
                }
                let chosen = candidates[next_source_cursor % candidates.len()];
                next_source_cursor = next_source_cursor.wrapping_add(1);
                retry_assignments[chosen].push(part_idx);
            }

            // If the cooldown filter left us with nothing to dial, sleep
            // until the soonest cooldown expires and re-evaluate WITHOUT
            // consuming a retry round. (The retry budget exists to bound
            // genuine retry attempts, not to be spent waiting on
            // cooldowns.)
            let assigned_count: usize =
                retry_assignments.iter().map(|v| v.len()).sum();
            if assigned_count == 0 {
                // Find the soonest cooldown expiry among sources that
                // actually have at least one needed part.
                let mut next_eligible: Option<std::time::Duration> = None;
                for (src_idx, source) in all_sources.iter().enumerate() {
                    let has_useful_part = sorted_incomplete.iter().any(|&p| {
                        source.available_parts.is_empty()
                            || source.available_parts.get(p).copied().unwrap_or(false)
                    });
                    if !has_useful_part {
                        continue;
                    }
                    let key = (source.peer_ip.clone(), source.peer_port);
                    let remaining = match source_dial_history.get(&key) {
                        Some(t) => source_retry_cooldown
                            .checked_sub(now.duration_since(*t))
                            .unwrap_or_default(),
                        None => std::time::Duration::ZERO,
                    };
                    next_eligible = Some(match next_eligible {
                        Some(cur) => cur.min(remaining),
                        None => remaining,
                    });
                    let _ = src_idx;
                }
                match next_eligible {
                    None => {
                        // No source has any of the parts we still need —
                        // retry rounds can't help. Fall out of the loop
                        // and let the outer logic re-queue the transfer.
                        info!("Retry round budget unused: no source advertises any of the {} remaining parts", sorted_incomplete.len());
                        break;
                    }
                    Some(d) if d.is_zero() => {
                        // Shouldn't happen given assigned_count == 0,
                        // but defend against an infinite tight loop.
                        warn!("Retry assignment empty despite eligible sources — bailing to avoid loop");
                        break;
                    }
                    Some(wait) => {
                        info!(
                            "Retry round {}/{}: all candidate sources on cooldown, sleeping {:.1}s before re-evaluating",
                            retry_round + 1,
                            max_retry_rounds,
                            wait.as_secs_f64(),
                        );
                        tokio::time::sleep(wait).await;
                        // Loop back without incrementing retry_round so
                        // a cooldown-only round doesn't burn the budget.
                        continue;
                    }
                }
            }

            retry_round += 1;
            warn!(
                "Retry round {}/{}: {} incomplete parts, dialing {} source(s)",
                retry_round,
                max_retry_rounds,
                incomplete.len(),
                retry_assignments.iter().filter(|v| !v.is_empty()).count(),
            );

            // Record dial timestamps for every source we're about to
            // retry, so subsequent rounds (or a new round triggered by
            // the cooldown sleep above) skip them until the cooldown
            // window expires.
            for (src_idx, parts) in retry_assignments.iter().enumerate() {
                if parts.is_empty() {
                    continue;
                }
                let s = &all_sources[src_idx];
                source_dial_history.insert((s.peer_ip.clone(), s.peer_port), now);
            }

            let (retry_tx, mut retry_rx) = mpsc::channel::<(usize, i64)>(256);
            let tid = self.transfer_id.clone();
            let fs = self.file_size;
            let etx = event_tx.clone();
            let retry_agg_tracker = tracker.clone();
            let retry_agg = tokio::spawn(async move {
                while let Some((_source_idx, _bytes)) = retry_rx.recv().await {
                    let capped = {
                        let t = retry_agg_tracker.read().await;
                        t.completed_bytes().min(fs)
                    };
                    let _ = etx
                        .send(DownloadEvent::Progress {
                            transfer_id: tid.clone(),
                            downloaded: capped,
                            total: fs,
                        })
                        .await;
                }
            });

            let mut retry_handles = Vec::new();
            for (src_idx, parts) in retry_assignments.into_iter().enumerate() {
                if parts.is_empty() {
                    continue;
                }
                let source = all_sources[src_idx].clone();
                let tracker = tracker.clone();
                let part_path = part_path.clone();
                let file_hash = self.file_hash;
                let file_size = self.file_size;
                let user_hash = self.user_hash;
                let nickname = self.nickname.clone();
                let tcp_port = self.tcp_port;
                let udp_port = self.udp_port;
                let bw = self.bandwidth_limiter.clone();
                let retry_tx = retry_tx.clone();
                let ph = part_hashes.clone();
                let aich_m = shared_aich_master.clone();
                let ra = active_count.clone();
                let rq = queued_count.clone();
                let rsm = self.source_manager.clone();
                let rcm = self.credit_manager.clone();
                let rcmt = self.comment_manager.clone();

                let rcs = chunk_selector.clone();
                let ravail = all_sources[src_idx].available_parts.clone();
                let retx = event_tx.clone();
                let rtid = self.transfer_id.clone();
                let rbi = self.shared_buddy_info.clone();
                let rctrl = self.control.clone();
                let robf = self.obfuscation_enabled;
                let rserver = self.server_addr;
                let r_ember_hash = self.ember_hash;
                let r_nick = self.nickname.clone();
                let rfail_etx = event_tx.clone();
                let rfail_tid = self.transfer_id.clone();
                let rfail_ip = source.peer_ip.clone();
                let rfail_port = source.peer_port;
                let r_qw = queue_wait_secs;
                let r_shared_out = shared_part_file.clone();
                let r_epx = self.ember_payload.clone();
                let r_epx_gen = self.ember_payload_generation.clone();
                let r_aich_p = self.aich_pending.clone();
                let r_ipf = self.ip_filter.clone();
                let r_ban = self.banned_ips.clone();
                let r_ext = self.external_ip;
                let r_geo = self.geoip.clone();
                let r_fh = self.friend_hashes.clone();
                let r_sx_oh = self.sx_overhead.clone();
                let r_sem = conn_semaphore.clone();
                retry_handles.push(tokio::spawn(async move {
                    let _permit = match r_sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    if let Err(e) = download_parts_from_source(
                        src_idx, &source, &parts, tracker, &part_path,
                        &file_hash, file_size, &user_hash, &nickname,
                        tcp_port, udp_port, bw, retry_tx, ph, aich_m,
                        ra, rq, rsm, rcm, rcmt, Some(rcs), ravail,
                        Some(retx), rtid, rbi, rctrl, robf, rserver, r_qw,
                        Some(r_shared_out), r_epx, r_epx_gen,
                        r_aich_p,
                        r_ipf, r_ban, r_ext,
                        r_geo, r_fh,
                        r_ember_hash,
                        r_nick,
                        r_sx_oh,
                        // Retry round always re-dials; the original
                        // pre-established stream (if any) was consumed
                        // by the initial attempt and is no longer
                        // alive by the time we retry.
                        None,
                    )
                    .await {
                        if !super::transfer::is_queue_detached_error(&e.to_string()) {
                            let _ = rfail_etx.send(DownloadEvent::SourceDetail {
                                transfer_id: rfail_tid,
                                ip: rfail_ip,
                                port: rfail_port,
                                status: "failed".to_string(),
                                queue_rank: None,
                                speed: 0,
                                transferred: 0,
                                client_software: String::new(),
                                peer_name: String::new(),
                                failure_kind: Some(super::transfer::classify_error(&e.to_string())),
                                available_parts: None,
                                total_parts: None,
                                country_code: None,
                            }).await;
                            warn!("Retry source {} failed: {e:#}", src_idx);
                        }
                    }
                }));
            }

            drop(retry_tx);
            let retry_all_done = {
                let t = tracker.read().await;
                t.all_complete()
            };
            if retry_all_done {
                for h in retry_handles {
                    h.abort();
                    let _ = h.await;
                }
            } else {
                for h in retry_handles {
                    let _ = h.await;
                }
            }
            retry_agg.await?;
            // Stamp the round-end so the inter-round backoff at the
            // top of the next iteration can decide whether to sleep.
            last_round_end = Some(std::time::Instant::now());
        }

        // eMule-style: remaining incomplete parts are handled through normal
        // retry rounds above. Endgame: tighter request pipelining and (when ≤3
        // parts remain) chunk selection biases toward higher availability.

        // Check if all parts are complete
        let all_done = {
            let t = tracker.read().await;
            t.all_complete()
        };

        if all_done {
            let _ = event_tx
                .send(DownloadEvent::Verifying {
                    transfer_id: self.transfer_id.clone(),
                })
                .await;

            // Fast path: compute the file hash from already-verified part hashes
            // (no disk I/O). Falls back to full re-read if part hashes aren't available.
            let expected = hex::encode(self.file_hash);
            let num_parts = ((self.file_size + super::hash::PARTSIZE - 1) / super::hash::PARTSIZE) as usize;
            let ph = part_hashes.read().await;
            let can_use_fast_verify = self.file_size >= super::hash::PARTSIZE
                && !ph.is_empty()
                && ph.len() >= num_parts;

            let verified_ok = if can_use_fast_verify {
                let actual = super::hash::ed2k_hash_from_parts(&ph, self.file_size);
                drop(ph);
                if actual == expected {
                    info!("Multi-source download verified from part hashes (no re-read): {}", self.file_name);
                    true
                } else {
                    warn!(
                        "Multi-source hash mismatch from parts for {}: expected={}, got={} — falling back to full rehash",
                        self.file_name, expected, actual
                    );
                    let verify_path = part_path.clone();
                    match tokio::task::spawn_blocking(move || {
                        super::hash::ed2k_hash_file(&verify_path)
                    }).await {
                        Ok(Ok(h)) if h == expected => { info!("Full rehash matched for {}", self.file_name); true }
                        Ok(Ok(h)) => { warn!("Full rehash also mismatched for {}: got={}", self.file_name, h); false }
                        Ok(Err(e)) => { warn!("Full rehash failed for {}: {e}", self.file_name); false }
                        Err(e) => { warn!("Full rehash task failed for {}: {e}", self.file_name); false }
                    }
                }
            } else {
                drop(ph);
                let verify_path = part_path.clone();
                match tokio::task::spawn_blocking(move || {
                    super::hash::ed2k_hash_file(&verify_path)
                }).await {
                    Ok(Ok(actual)) if actual == expected => {
                        info!("Multi-source download complete and verified: {}", self.file_name);
                        true
                    }
                    Ok(Ok(actual)) => {
                        warn!(
                            "Multi-source download hash mismatch for {}: expected={}, got={}",
                            self.file_name, expected, actual
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

            if verified_ok {
                // Verification passed — safe to move file and clean up resume state.
                // Mark every part verified (covers < PARTSIZE single-part
                // files that never set per-part flags, and acts as a
                // belt-and-braces reset for multi-part files).
                {
                    let mut t = tracker.write().await;
                    t.mark_file_hash_verified();
                }
                let safe_name = crate::security::sanitize_filename(&self.file_name);
                let final_path = self.download_dir.join("Downloads").join(&safe_name);
                let pp = part_path.clone();
                let fp = final_path.clone();
                tokio::task::spawn_blocking(move || super::transfer::move_part_to_final(&pp, &fp))
                    .await
                    .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;
                {
                    let t = tracker.read().await;
                    t.delete_met();
                }
                let _ = event_tx
                    .send(DownloadEvent::Completed {
                        transfer_id: self.transfer_id.clone(),
                    })
                    .await;
            } else {
                // Hash failed — re-open all parts as incomplete so retries
                // can re-download them (we can't identify which parts are
                // corrupt without per-part hashes).
                let (corrected_bytes, snap) = {
                    let mut t = tracker.write().await;
                    for i in 0..t.part_count {
                        t.mark_incomplete(i);
                    }
                    warn!(
                        "Final hash failed for {} — re-opened all {} parts for retry",
                        self.file_name, t.part_count
                    );
                    (t.completed_bytes(), t.snapshot_for_save())
                };
                // Awaited save here: this is a terminal failure path and
                // we want the .part.met on disk to reflect the reset
                // before signaling the failure (so a quick restart picks
                // up the corrected gap list).
                super::part_tracker::save_snapshot_async(snap).await;
                let _ = event_tx
                    .send(DownloadEvent::Progress {
                        transfer_id: self.transfer_id.clone(),
                        downloaded: corrected_bytes.min(self.file_size),
                        total: self.file_size,
                    })
                    .await;
                let _ = event_tx
                    .send(DownloadEvent::Failed {
                        transfer_id: self.transfer_id.clone(),
                        error: "Final hash verification failed — .part preserved for retry".to_string(),
                        failure_kind: super::transfer::SourceFailureKind::Permanent,
                    })
                    .await;
            }
        } else {
            let remaining = {
                let t = tracker.read().await;
                t.part_count - t.completed_count()
            };
            let snap = {
                let t = tracker.read().await;
                t.snapshot_for_save()
            };
            super::part_tracker::save_snapshot_async(snap).await;
            let _ = event_tx
                .send(DownloadEvent::Failed {
                    transfer_id: self.transfer_id.clone(),
                    error: format!("{remaining} parts still incomplete after retries"),
                    failure_kind: super::transfer::SourceFailureKind::Transient,
                })
                .await;
        }

        if let Some(ref registry) = self.tracker_registry {
            if let Ok(mut reg) = registry.lock() {
                reg.remove(&self.transfer_id);
            }
        }

        Ok(())
    }
}

/// Maximum distinct in-flight compressed blocks per download session.
/// A hostile peer could otherwise stream many `OP_COMPRESSEDPART*` packets
/// with different `start` keys, each buffering up to
/// `MAX_DECOMPRESSED_PART` bytes, and multiply our memory footprint. eMule
/// negotiates at most a few outstanding requested blocks per session; 16
/// is comfortably above any legitimate pipelining depth.
const MAX_PENDING_COMPRESSED_BLOCKS: usize = 16;

fn append_compressed_chunk_ms(
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
    // Memory DoS guard: refuse to track more than N concurrent compressed
    // blocks per connection. Allow existing `start` keys to keep growing
    // (legitimate continuation); only reject genuinely new entries once the
    // map is full.
    if !pending.contains_key(&start) && pending.len() >= MAX_PENDING_COMPRESSED_BLOCKS {
        anyhow::bail!(
            "too many concurrent compressed blocks from peer ({} open, max {})",
            pending.len(),
            MAX_PENDING_COMPRESSED_BLOCKS
        );
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
        let decompressed = decompress_ed2k_part_ms(data)?;
        pending.remove(&start);
        Ok(Some(decompressed))
    } else {
        Ok(None)
    }
}

async fn download_parts_from_source(
    _src_idx: usize,
    source: &DownloadSource,
    parts: &[usize],
    tracker: Arc<RwLock<PartTracker>>,
    part_path: &std::path::Path,
    file_hash: &[u8; 16],
    file_size: u64,
    user_hash: &[u8; 16],
    nickname: &str,
    tcp_port: u16,
    udp_port: u16,
    bw: Arc<BandwidthLimiter>,
    progress_tx: mpsc::Sender<(usize, i64)>,
    shared_part_hashes: Arc<RwLock<Vec<[u8; 16]>>>,
    shared_aich_master: Arc<RwLock<Option<[u8; 20]>>>,
    active_count: Arc<AtomicU32>,
    queued_count: Arc<AtomicU32>,
    source_mgr: Option<Arc<RwLock<SourceManager>>>,
    credit_mgr: Option<Arc<RwLock<CreditManager>>>,
    comment_mgr: Option<Arc<RwLock<CommentManager>>>,
    chunk_sel: Option<Arc<RwLock<ChunkSelector>>>,
    source_available: Vec<bool>,
    event_tx: Option<mpsc::Sender<DownloadEvent>>,
    transfer_id: String,
    buddy_info: Option<super::upload::SharedBuddyInfo>,
    control: Arc<TransferControl>,
    obfuscation_enabled: bool,
    server_addr: Option<SocketAddr>,
    queue_wait_secs: u64,
    shared_output: Option<super::write_coordinator::PartFileWriter>,
    ember_payload: crate::network::ember::SharedEmberPayload,
    ember_payload_generation: crate::network::ember::EmberPayloadGeneration,
    aich_pending: Option<super::transfer::SharedAichPending>,
    sx_ip_filter: Option<crate::network::kad::ip_filter::SharedIpFilter>,
    sx_banned_ips: Option<super::upload::SharedBannedIps>,
    sx_external_ip: Option<std::net::Ipv4Addr>,
    geoip: crate::geoip::GeoIpReader,
    friend_hashes: Option<Arc<RwLock<std::collections::HashSet<[u8; 16]>>>>,
    ember_hash: [u8; 16],
    our_nickname: String,
    sx_overhead: crate::storage::statistics::SharedSxOverheadCounters,
    // `pre_established`: if `Some`, skip TCP connect + obfuscation +
    // Hello + EmuleInfo because the upload listener already did all
    // of that for an inbound KAD/server callback. We adopt the
    // supplied stream and peer user-hash, default
    // `peer_secure_ident_level` to 3 (every client that reaches us
    // via callback is a modern eMule that advertises SecIdent v3 in
    // MISCOPTIONS1), and jump straight into the proactive SecIdent
    // kick-off + pre-file-control loop. This is the fix for the
    // wasted-callback bug where we were re-dialling LowID peers
    // that, by definition, can't accept inbound TCP — the new
    // outbound always failed at hello_wait. `None` preserves the
    // historical connect+handshake path used by all non-callback
    // sources (initial sources, KAD/server-discovered sources, etc.).
    pre_established: Option<EstablishedStream>,
) -> anyhow::Result<()> {
    use super::messages::*;
    use tokio::net::TcpStream;

    let addr: SocketAddr = format!("{}:{}", source.peer_ip, source.peer_port).parse()?;
    let src_ip = addr.ip().to_string();
    let src_port = addr.port();
    let mut src_transferred: u64 = 0;
    // D12: bytes received from this peer since the last successful MD4
    // verification, grouped by (pending). We defer calling
    // `cm.add_downloaded(...)` until the part these bytes contributed to
    // actually verifies; on a Mismatch the bytes are dropped so the peer
    // gets no credit for corrupt data. Legit bytes contributed to a
    // multi-source part completion will be counted when any one peer's
    // task observes the Verified outcome.
    // Credit accrual is **per-part**. Without pipelining a single
    // counter sufficed (a session only has one part outstanding at a
    // time), but cross-part request pipelining can leave bytes for
    // part N+1 in flight while part N is being verified. If we lump
    // them, a part-N hash failure would also drop part-N+1's
    // legitimate bytes from the credit ledger. Keyed by part_idx;
    // entries are taken on `Verified` and dropped on `Mismatch`.
    let mut per_part_credit: HashMap<usize, u64> = HashMap::new();
    let mut early_upload_accept = false;
    let mut pending_secident_challenge: Option<u32> = None;
    // Parks an incoming OP_SECIDENTSTATE when the peer's RSA public key
    // hasn't arrived yet. Our signature response is over
    // `peer_pub_key || challenge` (eMule `CreateSignature`), which we
    // cannot construct without that key. Once the peer's OP_PUBLICKEY
    // shows up, the handler below replays the parked `(challenge, state)`
    // through `respond_to_secident_challenge`. Matches the deferred-sign
    // path in BaseClient.cpp:1907+ and is what lets the chicken-and-egg
    // "neither side has the other's key yet" case complete without
    // deadlock.
    let mut pending_peer_challenge: Option<(u32, u8)> = None;
    let mut epx_packets_received: u8 = 0;

    let is_sx_rejected = |ip: &Ipv4Addr, port: u16| -> bool {
        if let Some(ext_ip) = sx_external_ip {
            if *ip == ext_ip && port == tcp_port {
                return true;
            }
        }
        if let Some(ref filter) = sx_ip_filter {
            if let Ok(snap) = filter.read() {
                if snap.is_blocked(*ip) {
                    return true;
                }
            }
        }
        if let Some(ref banned) = sx_banned_ips {
            if let Ok(set) = banned.read() {
                if set.contains(ip) {
                    return true;
                }
            }
        }
        false
    };

    let mut src_client_software = String::new();
    let mut src_peer_name = String::new();
    let mut src_available_parts: Option<u32> = None;
    let mut src_total_parts: Option<u32> = None;
    let src_country_code: Option<String> = crate::geoip::lookup_country(&geoip, addr.ip());
    let mut ip_guard = InProgressGuard::new(tracker.clone());

    macro_rules! emit_source {
        ($status:expr, $qr:expr, $speed:expr) => {
            if let Some(ref etx) = event_tx {
                let _ = etx
                    .send(DownloadEvent::SourceDetail {
                        transfer_id: transfer_id.clone(),
                        ip: src_ip.clone(),
                        port: src_port,
                        status: $status.to_string(),
                        queue_rank: $qr,
                        speed: $speed,
                        transferred: src_transferred,
                        client_software: src_client_software.clone(),
                        peer_name: src_peer_name.clone(),
                        failure_kind: None,
                        available_parts: src_available_parts,
                        total_parts: src_total_parts,
                        country_code: src_country_code.clone(),
                    })
                    .await;
            }
        };
    }

    emit_source!("connecting", None, 0u64);
    check_control(&control).await?;

    type DynRead = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
    type DynWrite = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

    let our_client_id = sx_external_ip
        .map(|ip| u32::from_le_bytes(ip.octets()))
        .unwrap_or(0);

    // Variables produced by either the connect+handshake path below
    // or the pre-established adoption path. Single-assignment from
    // each branch; the rest of the function uses these uniformly.
    // Pre-declaring them here (instead of inside the connect path)
    // is what lets the new "use this stream" shortcut populate the
    // same variables without duplicating every downstream `let`.
    let connection_is_obfuscated: bool;
    let mut reader: DynRead;
    let mut writer: DynWrite;
    let peer_user_hash: [u8; 16];
    let mut hello_caps: PeerCapabilities;
    let mut peer_supports_large_files: bool;
    let mut peer_supports_multipacket: bool;
    let mut peer_supports_ext_multipacket: bool;
    let mut peer_supports_file_ident: bool;
    let mut peer_extended_requests_ver: u8;
    let mut peer_supports_source_ex2: bool;
    let mut peer_source_exchange_ver: u8;
    let mut peer_secure_ident_level: u8;
    let mut peer_supports_aich: bool;
    let mut peer_ember_hash: Option<[u8; 16]>;
    let mut deferred_packet: Option<(u8, u8, Vec<u8>)> = None;

    if let Some(es) = pre_established {
        // Pre-established (KAD/server callback) path: the upload-side
        // listener already did TCP + (maybe obfuscation) + Hello +
        // (maybe EmuleInfo) for this peer, so we adopt the supplied
        // stream and identity directly. Default capabilities to a
        // modest-but-correct set (SecIdent v3 because every modern
        // eMule advertises that in MISCOPTIONS1; everything else
        // conservatively false). Any EmuleInfo that arrives mid-flow
        // will overwrite these via the existing match arms below in
        // the file-status-wait phase. This is the bug fix for the
        // wasted callback: previously, a LowID peer that connected
        // back to us via callback would just have its metadata
        // injected into `new_source_rx`, triggering a fresh outbound
        // connect that always failed because LowID peers can't accept
        // inbound TCP.
        info!(
            "Source {} ({}) adopting pre-established callback stream (obf={})",
            _src_idx, addr, es.emule_info_done,
        );
        if let Some(sm) = &source_mgr {
            if let std::net::IpAddr::V4(v4) = addr.ip() {
                let mut sm = sm.write().await;
                sm.register_source(*file_hash, v4, addr.port());
            }
        }
        connection_is_obfuscated = es.emule_info_done;
        reader = es.reader;
        writer = es.writer;
        peer_user_hash = es.peer_user_hash;
        let mut caps = PeerCapabilities::default();
        caps.secure_ident_level = 3;
        caps.supports_secure_ident = true;
        hello_caps = caps;
        peer_supports_large_files = false;
        peer_supports_multipacket = false;
        peer_supports_ext_multipacket = false;
        peer_supports_file_ident = false;
        peer_extended_requests_ver = 0;
        peer_supports_source_ex2 = false;
        peer_source_exchange_ver = 1;
        peer_secure_ident_level = 3;
        peer_supports_aich = false;
        peer_ember_hash = None;
    } else {
        let stream = match tokio::time::timeout(
            std::time::Duration::from_secs(40),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(s)) => { tune_peer_stream(&s); s },
            Ok(Err(e)) => return Err(anyhow::anyhow!("stage:tcp_connect_timeout {e}")),
            Err(_) => return Err(anyhow::anyhow!("stage:tcp_connect_timeout timeout")),
        };

        // Register this source with the source manager
        if let Some(sm) = &source_mgr {
            if let std::net::IpAddr::V4(v4) = addr.ip() {
                let mut sm = sm.write().await;
                sm.register_source(*file_hash, v4, addr.port());
            }
        }

        // eMule BaseClient.cpp: only enable encryption when peer requests (bit 1)
        // or requires (bit 2) it. Merely supporting (bit 0) is not enough unless
        // we have a "prefer crypt" setting. Matching eMule's conservative default
        // avoids unnecessary obfuscation attempts that add latency and may fail.
        let peer_opts = source.peer_connect_options.unwrap_or(0);
        let should_try_obf = source.peer_user_hash.is_some()
            && (peer_opts & 0x06) != 0;
        let mut conn_is_obf = false;
        let (r0, w0): (DynRead, DynWrite) = if let Some(peer_hash) = source.peer_user_hash.filter(|_| should_try_obf) {
            debug!("Source {} has known peer hash metadata", _src_idx);
            let (raw_r, raw_w) = stream.into_split();
            let mut buf_r = tokio::io::BufReader::new(raw_r);
            let mut buf_w = tokio::io::BufWriter::new(raw_w);
            match tcp_obfuscation::negotiate_outgoing(&mut buf_r, &mut buf_w, &peer_hash).await {
                Ok((recv_key, send_key)) => {
                    conn_is_obf = true;
                    (
                        Box::new(tokio::io::BufReader::new(Rc4Reader::new(buf_r, recv_key))),
                        Box::new(tokio::io::BufWriter::new(Rc4Writer::new(buf_w, send_key))),
                    )
                }
                Err(e) => {
                    if peer_opts & 0x04 != 0 {
                        return Err(anyhow::anyhow!(
                            "stage:tcp_obfuscation peer requires crypt and obfuscation failed: {e}"
                        ));
                    }
                    debug!("Outgoing obfuscation failed for source {}: {e}; reconnecting plain", _src_idx);
                    let plain_stream = match tokio::time::timeout(
                        std::time::Duration::from_secs(40),
                        TcpStream::connect(addr),
                    )
                    .await
                    {
                        Ok(Ok(s)) => { tune_peer_stream(&s); s },
                        Ok(Err(err)) => return Err(anyhow::anyhow!("stage:tcp_connect_timeout {err}")),
                        Err(_) => return Err(anyhow::anyhow!("stage:tcp_connect_timeout timeout")),
                    };
                    let (r, w) = plain_stream.into_split();
                    (
                        Box::new(tokio::io::BufReader::new(r)),
                        Box::new(tokio::io::BufWriter::new(w)),
                    )
                }
            }
        } else {
            let (raw_r, raw_w) = stream.into_split();
            (
                Box::new(tokio::io::BufReader::new(raw_r)),
                Box::new(tokio::io::BufWriter::new(raw_w)),
            )
        };
        connection_is_obfuscated = conn_is_obf;
        reader = r0;
        writer = w0;

        // Hello handshake (include buddy tags if we have a buddy)
        let buddy = match &buddy_info {
            Some(bi) => bi.read().await.clone(),
            None => None,
        };
        let server_ip = server_addr.and_then(|addr| match addr.ip() {
            std::net::IpAddr::V4(v4) => Some(u32::from_le_bytes(v4.octets())),
            _ => None,
        }).unwrap_or(0);
        let server_port = server_addr.map(|addr| addr.port()).unwrap_or(0);
        let hello_options = HelloOptions {
            udp_port,
            kad_port: udp_port,
            supports_crypt_layer: obfuscation_enabled,
            requests_crypt_layer: obfuscation_enabled,
            requires_crypt_layer: false,
            supports_direct_udp_callback: false,
            supports_captcha: false,
            server_ip,
            server_port,
            kad_version: 0x09,
        };
        let hello_payload = build_hello_with_buddy_opts(
            user_hash,
            our_client_id,
            tcp_port,
            nickname,
            buddy,
            &hello_options,
        );
        write_packet_async_ms(&mut *writer, OP_EDONKEYHEADER, OP_HELLO, &hello_payload).await?;

        let (h_proto, h_opcode, hello_ans_data) = read_packet_timeout_ms(&mut *reader)
            .await
            .context("stage:hello_wait")?;
        if h_proto != OP_EDONKEYHEADER || h_opcode != OP_HELLOANSWER {
            anyhow::bail!("source {}: expected HelloAnswer, got proto=0x{h_proto:02X} op=0x{h_opcode:02X}", _src_idx);
        }
        let (puh, hcaps) = parse_hello_answer(&hello_ans_data)
            .map_err(|e| {
                tracing::warn!("Source {}: failed to parse HelloAnswer: {e}", _src_idx);
                e
            })
            .unwrap_or_else(|_| {
                let mut peer_user_hash = [0u8; 16];
                if hello_ans_data.len() >= 16 {
                    peer_user_hash.copy_from_slice(&hello_ans_data[..16]);
                }
                (peer_user_hash, PeerCapabilities::default())
            });
        peer_user_hash = puh;
        hello_caps = hcaps;
        src_client_software = client_software_from_caps(&hello_caps);
        src_peer_name = hello_caps.peer_name.clone();
        peer_supports_large_files = hello_caps.supports_large_files;
        peer_supports_multipacket = hello_caps.supports_multi_packet;
        peer_supports_ext_multipacket = hello_caps.ext_multi_packet;
        peer_supports_file_ident = hello_caps.supports_file_ident;
        peer_extended_requests_ver = hello_caps.extended_requests_ver;
        peer_supports_source_ex2 = hello_caps.supports_source_ex2;
        peer_source_exchange_ver = hello_caps.source_exchange_ver;
        peer_secure_ident_level = hello_caps.secure_ident_level;
        peer_supports_aich = hello_caps.supports_aich;
        peer_ember_hash = hello_caps.ember_hash;

        let emule_payload = build_emule_info(udp_port, obfuscation_enabled, Some(&ember_hash), None);
        write_packet_async_ms(&mut *writer, OP_EMULEPROT, OP_EMULEINFO, &emule_payload).await?;

        match read_packet_timeout_ms(&mut *reader)
            .await
            .context("stage:emule_info_wait")
        {
            Ok((proto, opcode, payload)) => {
                if proto == OP_EMULEPROT && (opcode == OP_EMULEINFOANSWER || opcode == OP_EMULEINFO) {
                    merge_caps(&mut hello_caps, parse_emule_info(&payload));
                    let peer_udp = hello_caps.udp_port;
                    peer_supports_multipacket = hello_caps.supports_multi_packet;
                    peer_supports_ext_multipacket = hello_caps.ext_multi_packet;
                    peer_supports_file_ident = hello_caps.supports_file_ident;
                    peer_extended_requests_ver = hello_caps.extended_requests_ver;
                    peer_supports_source_ex2 = hello_caps.supports_source_ex2;
                    peer_source_exchange_ver = hello_caps.source_exchange_ver;
                    peer_secure_ident_level = hello_caps.secure_ident_level;
                    peer_supports_large_files = hello_caps.supports_large_files;
                    peer_supports_aich = hello_caps.supports_aich;
                    peer_ember_hash = hello_caps.ember_hash;
                    src_client_software = client_software_from_caps(&hello_caps);
                    if !hello_caps.peer_name.is_empty() {
                        src_peer_name = hello_caps.peer_name.clone();
                    }
                    if peer_udp > 0 {
                        if let Some(sm) = &source_mgr {
                            let mut sm = sm.write().await;
                            if let std::net::IpAddr::V4(v4) = addr.ip() {
                                sm.register_source_full(*file_hash, v4, addr.port(), peer_udp, peer_user_hash);
                            }
                        }
                    }
                    if opcode == OP_EMULEINFO {
                        let emule_answer = build_emule_info(udp_port, obfuscation_enabled, Some(&ember_hash), None);
                        let _ = write_packet_async_ms(&mut *writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &emule_answer).await;
                        debug!("Received peer OP_EMULEINFO from source {}, replied", _src_idx);
                    } else {
                        debug!("Got EmuleInfoAnswer from source {}", _src_idx);
                    }
                    pending_secident_challenge = super::transfer::maybe_send_secident_challenge(
                        &mut *writer,
                        credit_mgr.as_ref(),
                        peer_user_hash,
                        addr,
                        peer_secure_ident_level,
                    ).await?;
                } else {
                    deferred_packet = Some((proto, opcode, payload));
                }
            }
            Err(e) => {
                debug!("EmuleInfo exchange failed for source {}: {e}", _src_idx);
            }
        }
    }

    // Proactive SecIdent kick-off for paths that didn't already fire one.
    // Covers the modern-eMule fast path where the peer's HelloAnswer
    // carries CT_EMULE_VERSION — they treat `m_byInfopacketsReceived ==
    // IP_BOTH` as soon as Hello is processed (BaseClient.cpp:659-664)
    // and send OP_SECIDENTSTATE directly, so our first post-Hello
    // read arrives on a non-EmuleInfo opcode and we take the
    // `deferred_packet = Some(..)` branch above without challenging.
    // Without this call the peer sits waiting for our OP_SECIDENTSTATE
    // (it only ships OP_PUBLICKEY in response to ours, per
    // ListenSocket.cpp:1138), our deferred incoming SECIDENTSTATE
    // never gets replayed, and both sides settle at IS_NOTAVAILABLE —
    // downloads keep working but no credit-verified identity is ever
    // established for this peer. `maybe_send_secident_challenge` is a
    // no-op when the peer didn't advertise SecIdent or we have no
    // local keypair.
    if pending_secident_challenge.is_none() {
        pending_secident_challenge = super::transfer::maybe_send_secident_challenge(
            &mut *writer,
            credit_mgr.as_ref(),
            peer_user_hash,
            addr,
            peer_secure_ident_level,
        ).await?;
    }

    // Handle pre-file-control packets which may arrive before file requests.
    for _ in 0..3 {
        let (proto, opcode, payload) = if let Some(pkt) = deferred_packet.take() {
            pkt
        } else {
            match tokio::time::timeout(
                std::time::Duration::from_secs(3),
                read_packet_async_ms(&mut *reader),
            )
            .await
            {
                Ok(Ok(pkt)) => pkt,
                _ => break,
            }
        };

        match (proto, opcode) {
            (OP_EMULEPROT, OP_SECIDENTSTATE) if payload.len() >= 5 => {
                let state = payload[0];
                let challenge =
                    u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                // When the peer's state is IS_KEYANDSIGNEEDED (2) we have to
                // sign a message that includes THEIR public key, which only
                // arrives on OP_PUBLICKEY. If we haven't received their key
                // yet, park the challenge and replay from the OP_PUBLICKEY
                // handler below. Otherwise respond immediately. Without
                // this, `respond_to_secident_challenge` silently drops the
                // OP_SIGNATURE (sig len = 0) when `record.public_key` is
                // empty, the peer never gets our signature, and the
                // handshake never completes.
                let missing_peer_key = if state >= 2 {
                    if let Some(cm) = &credit_mgr {
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
                    debug!(
                        "Deferred SecIdent challenge from source {} — awaiting their public key",
                        _src_idx
                    );
                } else {
                    super::transfer::respond_to_secident_challenge(
                        &mut *writer,
                        credit_mgr.as_ref(),
                        state,
                        challenge,
                        addr,
                        peer_user_hash,
                        peer_secure_ident_level,
                        our_client_id,
                    ).await?;
                    debug!("Responded to SecIdent challenge from source {}", _src_idx);
                }
            }
            (OP_EMULEPROT, OP_PUBLICKEY) if payload.len() >= 2 => {
                let key_len = payload[0] as usize;
                if payload.len() >= 1 + key_len && key_len > 0 {
                    if let Some(cm) = &credit_mgr {
                        let mut cm = cm.write().await;
                        cm.set_public_key(peer_user_hash, payload[1..1 + key_len].to_vec());
                    }
                    // Replay a challenge we parked earlier because we
                    // didn't yet have the peer's key — now we can sign
                    // it and the peer finally gets our OP_SIGNATURE.
                    if let Some((challenge, state)) = pending_peer_challenge.take() {
                        super::transfer::respond_to_secident_challenge(
                            &mut *writer,
                            credit_mgr.as_ref(),
                            state,
                            challenge,
                            addr,
                            peer_user_hash,
                            peer_secure_ident_level,
                            our_client_id,
                        ).await?;
                        debug!(
                            "Replayed deferred SecIdent response to source {} after receiving their public key",
                            _src_idx
                        );
                    }
                    if pending_secident_challenge.is_none() {
                        pending_secident_challenge = super::transfer::maybe_send_secident_challenge(
                            &mut *writer,
                            credit_mgr.as_ref(),
                            peer_user_hash,
                            addr,
                            peer_secure_ident_level,
                        ).await?;
                    }
                }
            }
            (OP_EMULEPROT, OP_SIGNATURE) if payload.len() >= 2 => {
                super::transfer::handle_secident_signature(
                    credit_mgr.as_ref(),
                    peer_user_hash,
                    &mut pending_secident_challenge,
                    addr,
                    peer_secure_ident_level,
                    &payload,
                    our_client_id,
                ).await;
            }
            (OP_EMULEPROT, OP_EMULEINFOANSWER) | (OP_EMULEPROT, OP_EMULEINFO) => {
                merge_caps(&mut hello_caps, parse_emule_info(&payload));
                let peer_udp = hello_caps.udp_port;
                peer_supports_large_files = hello_caps.supports_large_files;
                peer_supports_multipacket = hello_caps.supports_multi_packet;
                peer_supports_ext_multipacket = hello_caps.ext_multi_packet;
                peer_supports_file_ident = hello_caps.supports_file_ident;
                peer_extended_requests_ver = hello_caps.extended_requests_ver;
                peer_supports_source_ex2 = hello_caps.supports_source_ex2;
                peer_source_exchange_ver = hello_caps.source_exchange_ver;
                peer_secure_ident_level = hello_caps.secure_ident_level;
                peer_supports_aich = hello_caps.supports_aich;
                peer_ember_hash = hello_caps.ember_hash;
                src_client_software = client_software_from_caps(&hello_caps);
                if !hello_caps.peer_name.is_empty() {
                    src_peer_name = hello_caps.peer_name.clone();
                }
                if peer_udp > 0 {
                    if let Some(sm) = &source_mgr {
                        let mut sm = sm.write().await;
                        if let std::net::IpAddr::V4(v4) = addr.ip() {
                            sm.register_source_full(*file_hash, v4, addr.port(), peer_udp, peer_user_hash);
                        }
                    }
                }
                if opcode == OP_EMULEINFO {
                    let emule_answer = build_emule_info(udp_port, obfuscation_enabled, Some(&ember_hash), None);
                    let _ = write_packet_async_ms(&mut *writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &emule_answer).await;
                    debug!("Received delayed peer OP_EMULEINFO from source {}, replied", _src_idx);
                } else {
                    debug!("Got delayed EmuleInfoAnswer from source {}", _src_idx);
                }
            }
            (OP_EDONKEYHEADER, OP_ACCEPTUPLOADREQ) => {
                early_upload_accept = true;
                debug!("Received early AcceptUploadReq from source {}", _src_idx);
            }
            (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE) if epx_packets_received < crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION => {
                sx_overhead.record_download((6 + payload.len()) as u64);
                epx_packets_received += 1;
                info!("Received early EPX from source {} during pre-file-control ({} bytes)", _src_idx, payload.len());
                match crate::network::ember::parse_exchange_payload(&payload) {
                    Ok(result) if !result.files.is_empty() || !result.peers.is_empty() => {
                        let (epx_entries, aich_roots) = super::transfer::epx_result_to_entries(&result);
                        let epx_peers = result.peers.into_iter().map(|p| (p.ip, p.tcp_port)).collect();
                        if let Some(ref etx) = event_tx {
                            let _ = etx.send(DownloadEvent::EmberSources {
                                transfer_id: transfer_id.clone(),
                                entries: epx_entries,
                                aich_roots,
                                ember_peers: epx_peers,
                            }).await;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => debug!("Failed to parse early EPX from source {}: {e}", _src_idx),
                }
            }
            (OP_EMULEPROT, OP_EMBER_FRIEND_REQ) => {
                if let (Some(eh), Some(ref etx)) = (peer_ember_hash, &event_tx) {
                    let nick = std::str::from_utf8(&payload).unwrap_or("").to_string();
                    info!("Received early friend request from source {} (nick='{}')", _src_idx, nick);
                    let _ = etx.send(DownloadEvent::EmberFriendRequest {
                        ember_hash: eh,
                        nickname: nick,
                        peer_ip: addr.ip().to_string(),
                        peer_port: addr.port(),
                    }).await;
                }
            }
            _ => {
                deferred_packet = Some((proto, opcode, payload));
                break;
            }
        }
    }

    // Ember Peer Exchange: if peer is a Ember client, send our source list.
    // Snapshot the generation we sent so the periodic-resend loop below
    // (line ~3192) can correctly detect rebuilds that happen during the
    // file-status-wait / queue-wait window. Capturing the generation at
    // data-loop start instead — which the original code did — silently
    // lost every EPX update produced while we were queued (often the
    // most useful ones, since other sources arrived and shifted the
    // shareable set).
    info!("Source {}: is_ember={}, mod_version='{}', ember_hash={}",
        _src_idx, hello_caps.is_ember, hello_caps.mod_version,
        peer_ember_hash.map(|h| hex::encode(h)).unwrap_or_else(|| "none".to_string()));
    let mut initial_epx_sent_generation: Option<u64> = None;
    if hello_caps.is_ember {
        let sent_gen = ember_payload_generation.load(std::sync::atomic::Ordering::Relaxed);
        let epx_data = ember_payload.read().await.clone();
        if !epx_data.is_empty() {
            info!("Sending EPX to Ember source {} ({} bytes, gen {})", _src_idx, epx_data.len(), sent_gen);
            let _ = write_packet_async_ms(&mut *writer, OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE, &*epx_data).await;
            sx_overhead.record_upload((6 + epx_data.len()) as u64);
            initial_epx_sent_generation = Some(sent_gen);
        } else {
            info!("EPX payload empty, skipping EPX send to source {}", _src_idx);
        }
        if let std::net::IpAddr::V4(v4) = addr.ip() {
            let peer_tcp = addr.port();
            if peer_tcp > 0 && !crate::security::is_special_use_v4(v4) {
                if let Some(ref etx) = event_tx {
                    let _ = etx.send(DownloadEvent::EmberPeerDiscovered {
                        ip: v4,
                        tcp_port: peer_tcp,
                    }).await;
                }
            }
        }
    }

    let peer_is_friend = if let (Some(ref fh), Some(eh)) = (&friend_hashes, peer_ember_hash) {
        fh.read().await.contains(&eh)
    } else {
        false
    };
    if hello_caps.is_ember && peer_is_friend {
        info!("Sending friend request to Ember source {}", _src_idx);
        let nick_bytes = our_nickname.as_bytes();
        let _ = write_packet_async_ms(&mut *writer, OP_EMULEPROT, OP_EMBER_FRIEND_REQ, nick_bytes).await;
    } else if peer_is_friend {
        info!("Source {} is a friend but is_ember=false, skipping friend request", _src_idx);
    }
    if let (true, Some(eh)) = (peer_is_friend, peer_ember_hash) {
        if let Some(ref etx) = event_tx {
            let _ = etx.send(DownloadEvent::FriendSeen {
                ember_hash: eh,
                ip: addr.ip(),
                port: addr.port(),
            }).await;
        }
    }
    let is_ember_friend = hello_caps.is_ember && peer_is_friend;

    // File request in eMule order:
    // 1) OP_REQUESTFILENAME
    // 2) OP_SETREQFILEID (only needed for multipart files)
    let part_count = ed2k_part_count_for_size(file_size);
    let wire_part_count = ed2k_wire_part_count(file_size);
    let single_part = part_count <= 1;
    let completed_bitmap = if peer_extended_requests_ver > 0 {
        let t = tracker.read().await;
        let completed = t.completed_parts();
        let bitmap_len = (wire_part_count + 7) / 8;
        let mut bitmap = vec![0u8; bitmap_len];
        for (i, &done) in completed.iter().enumerate() {
            if done {
                bitmap[i / 8] |= 1 << (i % 8);
            }
        }
        bitmap
    } else {
        Vec::new()
    };
    let file_req = build_file_request(file_hash);
    let mut req_file_name_payload = file_req.clone();
    if peer_extended_requests_ver > 0 {
        req_file_name_payload.extend_from_slice(&(wire_part_count as u16).to_le_bytes());
        req_file_name_payload.extend_from_slice(&completed_bitmap);
        if peer_extended_requests_ver > 1 {
            req_file_name_payload.extend_from_slice(&0u16.to_le_bytes());
        }
    }
    let sx_allowed = if let Some(sm) = &source_mgr {
        let sm = sm.read().await;
        if let Ok(v4) = source.peer_ip.parse::<Ipv4Addr>() {
            sm.can_request_sources_for(file_hash, v4, source.peer_port)
        } else { true }
    } else { true };

    if peer_supports_file_ident || peer_supports_ext_multipacket || peer_supports_multipacket {
        // eMule-style multipacket file request.
        let mut mp = Vec::with_capacity(64 + req_file_name_payload.len());
        if peer_supports_file_ident {
            FileIdentifier {
                md4_hash: *file_hash,
                file_size: Some(file_size),
                aich_hash: None,
            }
            .write_identifier(&mut mp);
        } else if peer_supports_ext_multipacket {
            mp.extend_from_slice(file_hash);
            mp.extend_from_slice(&file_size.to_le_bytes()); // EXT: file size
        } else {
            mp.extend_from_slice(file_hash);
        }
        mp.push(OP_REQUESTFILENAME);
        if peer_extended_requests_ver > 0 {
            mp.extend_from_slice(&(wire_part_count as u16).to_le_bytes());
            mp.extend_from_slice(&completed_bitmap);
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
        write_packet_async_ms(&mut *writer, OP_EMULEPROT, mp_opcode, &mp).await?;
        if sx_allowed {
            if let Some(sm) = &source_mgr {
                let mut sm = sm.write().await;
                if let Ok(v4) = source.peer_ip.parse::<Ipv4Addr>() {
                    sm.mark_sx_sent(file_hash, v4, source.peer_port);
                }
            }
        }
    } else {
        write_packet_async_ms(&mut *writer, OP_EDONKEYHEADER, OP_REQUESTFILENAME, &req_file_name_payload).await?;
        if !single_part {
            write_packet_async_ms(&mut *writer, OP_EDONKEYHEADER, OP_SETREQFILEID, &file_req).await?;
        }
    }

    // Read responses (consume deferred packet first)
    let mut got_status = single_part;
    let mut got_filename = false;
    let mut peer_file_status: Option<Vec<bool>> = None;
    for fswait_round in 0..12u32 {
        let (proto, opcode, _payload) = if let Some(pkt) = deferred_packet.take() {
            pkt
        } else {
            read_packet_timeout_ms(&mut *reader)
                .await
                .context(format!("stage:file_status_wait (round {fswait_round}, got_filename={got_filename}, early_accept={early_upload_accept})"))?
        };
        if proto == OP_EDONKEYHEADER && opcode == OP_FILEREQANSNOFIL {
            anyhow::bail!("peer does not have the file");
        }
        if proto == OP_EDONKEYHEADER && opcode == OP_ACCEPTUPLOADREQ {
            early_upload_accept = true;
            debug!("Received early AcceptUploadReq during file-status wait from source {}", _src_idx);
            continue;
        }
        if proto == OP_EMULEPROT && (opcode == OP_EMULEINFOANSWER || opcode == OP_EMULEINFO) {
            merge_caps(&mut hello_caps, parse_emule_info(&_payload));
            let peer_udp = hello_caps.udp_port;
            peer_supports_large_files = hello_caps.supports_large_files;
            peer_supports_file_ident = hello_caps.supports_file_ident;
            peer_supports_source_ex2 = hello_caps.supports_source_ex2;
            peer_source_exchange_ver = hello_caps.source_exchange_ver;
            peer_secure_ident_level = hello_caps.secure_ident_level;
            peer_supports_aich = hello_caps.supports_aich;
            peer_ember_hash = hello_caps.ember_hash;
            src_client_software = client_software_from_caps(&hello_caps);
            if !hello_caps.peer_name.is_empty() {
                src_peer_name = hello_caps.peer_name.clone();
            }
            if peer_udp > 0 {
                if let Some(sm) = &source_mgr {
                    let mut sm = sm.write().await;
                    if let std::net::IpAddr::V4(v4) = addr.ip() {
                        sm.register_source_full(*file_hash, v4, addr.port(), peer_udp, peer_user_hash);
                    }
                }
            }
            if opcode == OP_EMULEINFO {
                let emule_answer = build_emule_info(udp_port, obfuscation_enabled, Some(&ember_hash), None);
                let _ = write_packet_async_ms(&mut *writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &emule_answer).await;
                debug!("Received peer OP_EMULEINFO from source {} during file-status wait, replied", _src_idx);
            } else {
                debug!("Ignoring delayed EmuleInfoAnswer from source {} during file-status wait", _src_idx);
            }
            continue;
        }
        if proto == OP_EMULEPROT && opcode == OP_PUBLICKEY && !_payload.is_empty() {
            let key = if _payload.len() >= 2 && _payload[0] as usize == _payload.len() - 1 {
                _payload[1..].to_vec()
            } else {
                _payload.clone()
            };
            if let Some(cm) = &credit_mgr {
                let mut cm = cm.write().await;
                cm.set_public_key(peer_user_hash, key);
            }
            // Replay any parked challenge now that we have the peer's key
            // (same deferred-sign path as the pre-file-control handler
            // above — see that block's comment for the full rationale).
            if let Some((challenge, state)) = pending_peer_challenge.take() {
                super::transfer::respond_to_secident_challenge(
                    &mut *writer,
                    credit_mgr.as_ref(),
                    state,
                    challenge,
                    addr,
                    peer_user_hash,
                    peer_secure_ident_level,
                    our_client_id,
                ).await?;
                debug!(
                    "Replayed deferred SecIdent response to source {} during file-status wait",
                    _src_idx
                );
            }
            if pending_secident_challenge.is_none() {
                pending_secident_challenge = super::transfer::maybe_send_secident_challenge(
                    &mut *writer,
                    credit_mgr.as_ref(),
                    peer_user_hash,
                    addr,
                    peer_secure_ident_level,
                ).await?;
            }
            continue;
        }
        if proto == OP_EMULEPROT && opcode == OP_SECIDENTSTATE && _payload.len() >= 5 {
            let state = _payload[0];
            let challenge = u32::from_le_bytes([_payload[1], _payload[2], _payload[3], _payload[4]]);
            let missing_peer_key = if state >= 2 {
                if let Some(cm) = &credit_mgr {
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
                super::transfer::respond_to_secident_challenge(
                    &mut *writer,
                    credit_mgr.as_ref(),
                    state,
                    challenge,
                    addr,
                    peer_user_hash,
                    peer_secure_ident_level,
                    our_client_id,
                ).await?;
            }
            continue;
        }
        if proto == OP_EMULEPROT && opcode == OP_SIGNATURE && _payload.len() >= 2 {
            super::transfer::handle_secident_signature(
                credit_mgr.as_ref(),
                peer_user_hash,
                &mut pending_secident_challenge,
                addr,
                peer_secure_ident_level,
                &_payload,
                our_client_id,
            ).await;
            continue;
        }
        if proto == OP_EMULEPROT && opcode == OP_FILEDESC && _payload.len() >= 5 {
            let rating = _payload[0];
            let clen = u32::from_le_bytes([_payload[1], _payload[2], _payload[3], _payload[4]]) as usize;
            if clen.checked_add(5).map_or(false, |need| _payload.len() >= need) {
                let comment = String::from_utf8_lossy(&_payload[5..5+clen]).to_string();
                if let Some(cm) = &comment_mgr {
                    let mut cm = cm.write().await;
                    cm.add_peer_comment(&hex::encode(file_hash), addr.to_string(), rating, comment.clone(), 0);
                }
                debug!("Peer comment from source {} during file-status: rating={rating}, comment='{comment}'", _src_idx);
            }
            continue;
        }
        if proto == OP_EMULEPROT && opcode == OP_EMBER_SOURCEEXCHANGE && epx_packets_received < crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION {
            sx_overhead.record_download((6 + _payload.len()) as u64);
            epx_packets_received += 1;
            info!("Received EPX from source {} during file-status-wait ({} bytes)", _src_idx, _payload.len());
            match crate::network::ember::parse_exchange_payload(&_payload) {
                Ok(result) if !result.files.is_empty() || !result.peers.is_empty() => {
                    let (epx_entries, aich_roots) = super::transfer::epx_result_to_entries(&result);
                    let epx_peers = result.peers.into_iter().map(|p| (p.ip, p.tcp_port)).collect();
                    if let Some(ref etx) = event_tx {
                        let _ = etx.send(DownloadEvent::EmberSources {
                            transfer_id: transfer_id.clone(),
                            entries: epx_entries,
                            aich_roots,
                            ember_peers: epx_peers,
                        }).await;
                    }
                }
                Ok(_) => {}
                Err(e) => debug!("Failed to parse EPX from source {} during file-status-wait: {e}", _src_idx),
            }
            continue;
        }
        if proto == OP_EMULEPROT && opcode == OP_EMBER_FRIEND_REQ {
            if let (Some(eh), Some(ref etx)) = (peer_ember_hash, &event_tx) {
                let nick = std::str::from_utf8(&_payload).unwrap_or("").to_string();
                info!("Received friend request from source {} during file-status-wait (nick='{}')", _src_idx, nick);
                let _ = etx.send(DownloadEvent::EmberFriendRequest {
                    ember_hash: eh,
                    nickname: nick,
                    peer_ip: addr.ip().to_string(),
                    peer_port: addr.port(),
                }).await;
            }
            continue;
        }
        if proto == OP_EDONKEYHEADER && opcode == OP_REQFILENAMEANSWER {
            got_filename = true;
            continue;
        }
        if proto == OP_EDONKEYHEADER && opcode == OP_FILESTATUS {
            if let Ok((status_hash, parts_vec)) = parse_file_status(&_payload) {
                if status_hash != *file_hash {
                    debug!("Source {} OP_FILESTATUS hash mismatch, ignoring", _src_idx);
                    continue;
                }
                let parts_vec = if parts_vec.is_empty() {
                    debug!("Source {} file status: part_count=0 → peer has complete file ({} parts)", _src_idx, part_count);
                    vec![true; part_count]
                } else {
                    debug!("Source {} file status: {}/{} parts available", _src_idx, parts_vec.iter().filter(|&&p| p).count(), parts_vec.len());
                    let mut padded = parts_vec;
                    if padded.len() < part_count {
                        padded.resize(part_count, false);
                    }
                    padded
                };
                peer_file_status = Some(parts_vec);
            }
            got_status = true;
            break;
        }
        if proto == OP_EMULEPROT
            && (opcode == OP_MULTIPACKETANSWER || opcode == OP_MULTIPACKETANSWER_EXT2)
        {
            if let Ok(mp) = parse_multipacket_answer(&_payload, opcode) {
                let local_ident = FileIdentifier {
                    md4_hash: *file_hash,
                    file_size: Some(file_size),
                    aich_hash: None,
                };
                if mp.file_hash != *file_hash
                    || mp.file_identifier.as_ref().map(|id| !local_ident.compare_relaxed(id)).unwrap_or(false)
                {
                    continue;
                }
                if mp.no_file {
                    anyhow::bail!("peer does not have the file");
                }
                if mp.file_name.is_some() {
                    got_filename = true;
                }
                if let Some(parts_vec) = mp.file_status {
                    let parts_vec = if parts_vec.is_empty() {
                        debug!("Source {} multipacket file status: part_count=0 → peer has complete file ({} parts)", _src_idx, part_count);
                        vec![true; part_count]
                    } else {
                        debug!("Source {} multipacket file status: {}/{} parts available", _src_idx, parts_vec.iter().filter(|&&p| p).count(), parts_vec.len());
                        let mut padded = parts_vec;
                        if padded.len() < part_count {
                            padded.resize(part_count, false);
                        }
                        padded
                    };
                    peer_file_status = Some(parts_vec);
                    got_status = true;
                    break;
                }
            }
        }
    }
    if !got_status && (got_filename || early_upload_accept) {
        debug!("Source {} proceeding without FileStatus (filename-only handshake fallback)", _src_idx);
        got_status = true;
    }
    if !got_status {
        anyhow::bail!("never received FileStatus");
    }

    // Track whether this source had pre-populated availability before we
    // learn the wire status — used later to avoid double-counting in ChunkSelector.
    let had_preexisting_availability = !source_available.is_empty();

    // Update source availability with the actual file status from the peer.
    // Without this, server-sourced peers (who have empty available_parts) are
    // assumed to have ALL parts, causing us to request parts they don't have.
    let source_available = if let Some(ref pfs) = peer_file_status {
        pfs.clone()
    } else {
        source_available
    };

    if let Some(ref pfs) = peer_file_status {
        src_available_parts = Some(pfs.iter().filter(|&&p| p).count() as u32);
        src_total_parts = Some(pfs.len() as u32);
    } else if single_part {
        src_available_parts = Some(1);
        src_total_parts = Some(1);
    } else if got_status {
        src_available_parts = Some(part_count as u32);
        src_total_parts = Some(part_count as u32);
    }
    debug!(
        "Source {} ({}) parts resolved: available={:?} total={:?}",
        _src_idx, addr, src_available_parts, src_total_parts
    );

    // Filter pre-assigned parts to only those the peer actually has
    let mut filtered_parts: Vec<usize> = parts.iter().copied().filter(|&p| {
        source_available.is_empty() || source_available.get(p).copied().unwrap_or(false)
    }).collect();

    if filtered_parts.is_empty() {
        if let Some(cs) = &chunk_sel {
            let cs = cs.read().await;
            let t = tracker.read().await;
            let completed = t.completed_parts().to_vec();
            let in_prog = t.in_progress.clone();
            let remaining = t.remaining_count();
            let pc = t.part_count;
            let gap_bytes = t.part_gap_bytes_vec();
            drop(t);
            if remaining > 0 {
                let avail = if source_available.is_empty() {
                    vec![true; pc]
                } else {
                    source_available.clone()
                };
                let pp = control.is_preview_priority();
                let prefer_higher = remaining <= 3 && pc > 1;
                let active: Vec<usize> = in_prog.iter().enumerate()
                    .filter(|(_, &ip)| ip).map(|(i, _)| i).collect();
                if let Some(p) = cs.select_part(&completed, &in_prog, &avail, &active, &gap_bytes, pp, prefer_higher) {
                    debug!("Source {} pre-assigned parts unavailable, dynamically selected part {}", _src_idx, p);
                    drop(cs);
                    let mut t = tracker.write().await;
                    t.set_in_progress(p, true);
                    drop(t);
                    ip_guard.mark(p);
                    filtered_parts.push(p);
                }
            }
        }
        if filtered_parts.is_empty() {
            emit_source!("no_needed_parts", None, 0u64);
            anyhow::bail!("peer has no parts we need");
        }
    }

    let parts = filtered_parts;

    // Update the ChunkSelector with the learned availability.
    // Skip if this source already had pre-populated available_parts (counted
    // in the initial update_frequencies call) to avoid double-counting.
    // Sources counted here are decremented when the task exits (see below).
    let wire_counted_avail: Option<Vec<bool>> = if !had_preexisting_availability {
        if let Some(ref pfs) = peer_file_status {
            if let Some(cs) = &chunk_sel {
                let mut cs = cs.write().await;
                for (i, &has) in pfs.iter().enumerate() {
                    if i < cs.part_frequency.len() && has {
                        cs.part_frequency[i] = cs.part_frequency[i].saturating_add(1);
                    }
                }
                cs.total_sources = cs.total_sources.saturating_add(1);
            }
            Some(pfs.clone())
        } else {
            None
        }
    } else {
        None
    };

    // Request part hashset if not already populated (first source to connect does this)
    {
        let existing = shared_part_hashes.read().await;
        if existing.is_empty() {
            drop(existing);
            if peer_supports_file_ident {
                let hashset_req2 = build_hashset_request2(file_hash, file_size, None, true, false);
                write_packet_async_ms(
                    &mut *writer,
                    OP_EMULEPROT,
                    OP_HASHSETREQUEST2,
                    &hashset_req2,
                )
                .await?;
            } else {
                let hashset_req = build_hashset_request(file_hash);
                write_packet_async_ms(
                    &mut *writer,
                    OP_EDONKEYHEADER,
                    OP_HASHSETREQ,
                    &hashset_req,
                )
                .await?;
            }
            // Read up to 5 packets waiting for the hashset answer.
            // The peer may interleave SecIdent or other control packets.
            for _hs_attempt in 0..5u32 {
                match read_packet_timeout_ms(&mut *reader)
                    .await
                    .context("stage:hashset_wait")
                {
                    Ok((proto, opcode, payload))
                        if proto == OP_EDONKEYHEADER && opcode == OP_HASHSETANSWER =>
                    {
                        if let Ok((_h, hashes)) = parse_hashset_answer(&payload) {
                            debug!("Got hashset with {} part hashes from source {}", hashes.len(), _src_idx);
                            if super::transfer::verify_hashset(&file_hash, &hashes, file_size) {
                                let mut ph = shared_part_hashes.write().await;
                                if ph.is_empty() {
                                    *ph = hashes;
                                }
                            } else {
                                warn!("Hashset from source {} failed verification, discarding", _src_idx);
                            }
                        }
                        break;
                    }
                    Ok((proto, opcode, payload))
                        if proto == OP_EMULEPROT && opcode == OP_HASHSETANSWER2 =>
                    {
                        if let Ok(resp) = parse_hashset_answer2(&payload) {
                            let local_ident = FileIdentifier {
                                md4_hash: *file_hash,
                                file_size: Some(file_size),
                                aich_hash: None,
                            };
                            if local_ident.compare_relaxed(&resp.identifier) {
                                // Pin the AICH master hash ONLY after the
                                // accompanying MD4 hashset verifies against
                                // the file's ed2k hash. This prevents a
                                // first-wins peer from pinning a bogus
                                // master that is never tied to a verified
                                // file identity (see audit D2). If MD4
                                // hashes are missing or bad, we defer AICH
                                // pinning until a trustworthy source
                                // arrives or the EPX-time check accepts it.
                                let md4_ok = resp
                                    .md4_hashes
                                    .as_ref()
                                    .map(|h| {
                                        super::transfer::verify_hashset(&file_hash, h, file_size)
                                    })
                                    .unwrap_or(false);
                                if md4_ok {
                                    if let Some(hashes) = resp.md4_hashes {
                                        let mut ph = shared_part_hashes.write().await;
                                        if ph.is_empty() {
                                            *ph = hashes;
                                        }
                                    }
                                    if let Some(root) = resp.aich_master_hash {
                                        let mut am = shared_aich_master.write().await;
                                        if am.is_none() {
                                            *am = Some(root);
                                        }
                                        if let Some(part_hashes) = resp.aich_part_hashes.as_ref() {
                                            debug!(
                                                "Source {} provided HashSet2 AICH data: master={}, parts={}",
                                                _src_idx,
                                                hex::encode(root),
                                                part_hashes.len()
                                            );
                                        }
                                    }
                                } else if resp.aich_master_hash.is_some() {
                                    warn!(
                                        "HashSet2 from source {} had an AICH master but the MD4 hashset failed or was absent — deferring AICH pin",
                                        _src_idx
                                    );
                                }
                            }
                        }
                        break;
                    }
                    Ok((proto, opcode, _))
                        if proto == OP_EDONKEYHEADER && opcode == OP_ACCEPTUPLOADREQ =>
                    {
                        early_upload_accept = true;
                        debug!("Source {} received AcceptUploadReq while waiting for hashset — stopping hashset wait", _src_idx);
                        break;
                    }
                    Ok((proto, opcode, _)) => {
                        debug!("Source {} waiting for hashset, got proto=0x{proto:02X} op=0x{opcode:02X} — skipping", _src_idx);
                    }
                    Err(_) => {
                        debug!("No hashset answer from source {} (peer may not support it)", _src_idx);
                        break;
                    }
                }
            }
        }
    }

    // Request source exchange, throttled to eMule's SOURCECLIENTREASKS (40 min per source)
    let sx_allowed = if let Some(sm) = &source_mgr {
        let sm = sm.read().await;
        if let Ok(v4) = source.peer_ip.parse::<Ipv4Addr>() {
            sm.can_request_sources_for(file_hash, v4, source.peer_port)
        } else { true }
    } else { true };
    if sx_allowed {
        if peer_supports_source_ex2 {
            let mut sx2_req = Vec::with_capacity(19);
            sx2_req.push(SOURCEEXCHANGE2_VERSION);
            sx2_req.extend_from_slice(&0u16.to_le_bytes());
            sx2_req.extend_from_slice(file_hash);
            let _ = write_packet_async_ms(&mut *writer, OP_EMULEPROT, OP_REQUESTSOURCES2, &sx2_req).await;
            sx_overhead.record_upload((6 + sx2_req.len()) as u64);
        } else {
            let sx_req = build_file_request(file_hash);
            let _ = write_packet_async_ms(&mut *writer, OP_EMULEPROT, OP_REQUESTSOURCES, &sx_req).await;
            sx_overhead.record_upload((6 + sx_req.len()) as u64);
        }
        if let Some(sm) = &source_mgr {
            let mut sm = sm.write().await;
            if let Ok(v4) = source.peer_ip.parse::<Ipv4Addr>() {
                sm.mark_sx_sent(file_hash, v4, source.peer_port);
            }
        }
    }

    struct CountGuard {
        counter: Arc<AtomicU32>,
        armed: bool,
    }
    impl Drop for CountGuard {
        fn drop(&mut self) {
            if self.armed {
                self.counter.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    let mut queued_guard = CountGuard { counter: queued_count.clone(), armed: false };
    let mut _active_guard = CountGuard { counter: active_count.clone(), armed: false };

    if early_upload_accept {
        active_count.fetch_add(1, Ordering::Relaxed);
        _active_guard.armed = true;
        emit_source!("transferring", None, 0u64);
    } else {
        // Request upload slot
        let upload_req = build_file_request(file_hash);
        write_packet_async_ms(&mut *writer, OP_EDONKEYHEADER, OP_STARTUPLOADREQ, &upload_req).await?;

        queued_count.fetch_add(1, Ordering::Relaxed);
        queued_guard.armed = true;

        // Wait for the uploader to grant a slot. Don't re-request; eMule
        // uploaders push OP_ACCEPTUPLOADREQ when a slot opens.
        let queue_start = std::time::Instant::now();
        emit_source!("queued", None, 0u64);
        loop {
            check_control(&control).await?;
            if queue_start.elapsed().as_secs() > queue_wait_secs {
                emit_source!("failed", None, 0u64);
                anyhow::bail!("timed out waiting for upload slot");
            }
            let remaining = queue_wait_secs
                .saturating_sub(queue_start.elapsed().as_secs())
                .max(60);
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(remaining),
                read_packet_async_ms(&mut *reader),
            )
            .await;
            let (proto, opcode, payload) = match result {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    anyhow::bail!("stage:queue_detached connection lost while queued: {e}");
                }
                Err(_) => {
                    emit_source!("failed", None, 0u64);
                    anyhow::bail!("timed out waiting for upload slot");
                }
            };
            if proto == OP_EDONKEYHEADER && opcode == OP_ACCEPTUPLOADREQ {
                queued_guard.armed = false;
                queued_count.fetch_sub(1, Ordering::Relaxed);
                active_count.fetch_add(1, Ordering::Relaxed);
                _active_guard.armed = true;
                info!("Source {} ({}) accepted upload request — entering transfer (obfuscated={})", _src_idx, addr, connection_is_obfuscated);
                emit_source!("transferring", None, 0u64);
                break;
            }
            if proto == OP_EMULEPROT && opcode == OP_QUEUEFULL && payload.is_empty() {
                emit_source!("queue_full", None, 0u64);
                anyhow::bail!("peer queue is full");
            }
            if proto == OP_EDONKEYHEADER && opcode == OP_OUTOFPARTREQS {
                emit_source!("no_needed_parts", None, 0u64);
                anyhow::bail!("peer has no free upload slots (OutOfPartReqs)");
            }
            if proto == OP_EMULEPROT && opcode == OP_QUEUERANKING && payload.len() >= 2 {
                let rank = u16::from_le_bytes([payload[0], payload[1]]);
                emit_source!("queued", Some(rank as u32), 0u64);
            } else if proto == OP_EDONKEYHEADER && opcode == OP_QUEUERANK && payload.len() >= 4 {
                let rank = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                emit_source!("queued", Some(rank), 0u64);
            } else if proto == OP_EMULEPROT && opcode == OP_FILEDESC && payload.len() >= 5 {
                let rating = payload[0];
                let clen = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
                if clen.checked_add(5).map_or(false, |need| payload.len() >= need) {
                    let comment = String::from_utf8_lossy(&payload[5..5+clen]).to_string();
                    if let Some(cm) = &comment_mgr {
                        let mut cm = cm.write().await;
                        cm.add_peer_comment(&hex::encode(file_hash), addr.to_string(), rating, comment.clone(), 0);
                    }
                    debug!("Peer comment from source {} while queued: rating={rating}, comment='{comment}'", _src_idx);
                }
            } else {
                info!("Source {} ({}) queue wait: unhandled packet proto=0x{:02X} op=0x{:02X} ({} bytes)",
                    _src_idx, addr, proto, opcode, payload.len());
            }
        }
    }

    let output = if let Some(shared) = shared_output {
        shared
    } else {
        super::write_coordinator::PartFileWriter::open(
            part_path.to_path_buf(),
            super::write_coordinator::OpenMode::OpenExisting,
        )
        .await
        .map_err(|e| anyhow::anyhow!("open part file: {e}"))?
    };

    let mut peer_out_of_parts = false;
    let mut measured_speed: u64 = 0;
    let mut speed_start = std::time::Instant::now();
    let mut speed_bytes: u64 = 0;

    // Build dynamic part queue: start with pre-assigned parts, add more dynamically
    let mut part_queue: Vec<usize> = parts.to_vec();
    let mut queue_idx = 0;
    let mut last_periodic_save = std::time::Instant::now();
    const PERIODIC_SAVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

    #[derive(Clone, Copy)]
    enum PartHashOutcome {
        Verified,
        Mismatch,
        AichNarrowed,
        Unverified,
    }

    // Cross-part request pipelining.
    //
    // When the LAST OP_REQUESTPARTS batch of part N has been sent,
    // we eagerly pre-pick part N+1 and ship its FIRST batch on the
    // same TCP session. The peer's send queue then never drains
    // while we verify part N — which removes the round-trip stall
    // that otherwise shows up as a "speed → 0" gap and a wasted
    // Hello/SecIdent reconnect handshake.
    //
    // Wire-protocol compatibility: OP_REQUESTPARTS payloads are just
    // byte ranges of the file (the peer has no notion of "parts").
    // Block placement on receipt is purely offset-driven
    // (`output.write(start, …)` and `tracker.fill_range(start, end)`),
    // so cross-part interleave is harmless. The peer also doesn't
    // distinguish between requests for different parts — it just
    // services them in order.
    struct PipelinedNext {
        part_idx: usize,
        all_blocks: Vec<(u64, u64)>,
        batches: Vec<Vec<(u64, u64)>>,
        sent_idx: usize,
        needs_i64: bool,
    }
    let mut pipelined_next: Option<PipelinedNext> = None;

    while queue_idx < part_queue.len() {
        check_control(&control).await?;
        let part_idx = part_queue[queue_idx];
        queue_idx += 1;
        if peer_out_of_parts {
            break;
        }

        // Race-check: another source may have completed this part
        // while we were on the previous one. Cheap read-lock check.
        {
            let t = tracker.read().await;
            if t.is_part_complete(part_idx) {
                // Drop any stale pipelined state for this part (we'd
                // pipelined it but no longer need to) and move on.
                if pipelined_next.as_ref().map(|p| p.part_idx) == Some(part_idx) {
                    pipelined_next = None;
                }
                continue;
            }
        }

        let mut aich_recovery_data: Option<([u8; 20], Vec<u8>)> = None;
        let mut pending_compressed: HashMap<u64, PendingCompressedBlock> = HashMap::new();

        // Either resume from a pre-pipelined state (the previous
        // iteration's send-ahead already shipped the first batch
        // for this part) or compute fresh.
        let pipelined_for_this = pipelined_next
            .take()
            .filter(|p| p.part_idx == part_idx);
        let resumed = pipelined_for_this.is_some();
        let (all_blocks, batches, mut sent_idx, needs_i64) =
            if let Some(p) = pipelined_for_this {
                (p.all_blocks, p.batches, p.sent_idx, p.needs_i64)
            } else {
                let (all_blocks, _ps, _pe) = compute_part_blocks_ms(&tracker, part_idx).await;
                let batches: Vec<Vec<(u64, u64)>> = all_blocks
                    .chunks(MAX_BLOCKS_PER_REQUEST)
                    .map(|c| c.to_vec())
                    .collect();
                let needs_i64 = peer_supports_large_files
                    && all_blocks.iter().any(|&(_, end)| end > u32::MAX as u64);
                (all_blocks, batches, 0, needs_i64)
            };

        // Mark in_progress (idempotent — pipelined state already did this,
        // and the same flag may be set by another source piling on for
        // MAX_SOURCES_PER_PART-style behaviour).
        {
            let mut t = tracker.write().await;
            t.set_in_progress(part_idx, true);
        }
        ip_guard.mark(part_idx);

        let (remaining, gap_rem) = {
            let t = tracker.read().await;
            (t.remaining_count(), t.remaining_gap_bytes())
        };
        let max_outstanding =
            outstanding_requests_for_speed_ms(measured_speed, remaining, gap_rem);

        if all_blocks.is_empty() {
            debug!("Source {} part {} has no gaps — skipping", _src_idx, part_idx);
        } else if resumed {
            info!(
                "Source {} ({}) resuming pipelined part {}: {} batches sent ahead, {} more queued",
                _src_idx, addr, part_idx, sent_idx, batches.len() - sent_idx,
            );
        } else {
            info!("Source {} ({}) requesting part {}: {} blocks, {} batches, {} bytes (i64={})",
                _src_idx, addr, part_idx, all_blocks.len(), batches.len(),
                all_blocks.iter().map(|(s, e)| e - s).sum::<u64>(),
                needs_i64);
        }

        // Send initial batches up to max_outstanding. When `resumed=true`
        // some batches have already been sent via the previous
        // iteration's pipeline; `sent_idx` reflects that, so we pick up
        // exactly where the pipeline left off without re-sending or
        // missing any batch.
        //
        // Match eMule behaviour: only use OP_REQUESTPARTS_I64 when an
        // offset actually exceeds 32-bit range.  Many peers on the
        // network (eMule mods) do not implement the I64 handler and
        // silently drop the request, causing "accepted but no data"
        // timeouts.
        while sent_idx < batches.len() && sent_idx < max_outstanding {
            let batch = &batches[sent_idx];
            let (req_payload, req_proto, req_op) = if needs_i64 {
                (build_request_parts_i64(file_hash, batch), OP_EMULEPROT, OP_REQUESTPARTS_I64)
            } else {
                (build_request_parts(file_hash, batch), OP_EDONKEYHEADER, OP_REQUESTPARTS)
            };
            if sent_idx == 0 && !resumed {
                info!("Source {} ({}) sending OP_REQUESTPARTS: proto=0x{:02X} op=0x{:02X} len={} payload_hex={}",
                    _src_idx, addr, req_proto, req_op, req_payload.len(), hex::encode(&req_payload));
            }
            write_packet_async_ms(&mut *writer, req_proto, req_op, &req_payload).await?;
            sent_idx += 1;
        }

        let mut blocks_received_in_current_req: usize = 0;
        let mut completed_reqs: usize = 0;
        let mut consecutive_bad_blocks: u32 = 0;
        const MAX_CONSECUTIVE_BAD_BLOCKS: u32 = 5;
        let data_loop_start = std::time::Instant::now();
        let mut got_any_data = false;
        // eMule uses DOWNLOADTIMEOUT (100s) as a single timeout for both initial
        // and mid-transfer stalls.  We use 60s for the initial wait as a
        // compromise: gives slow uploaders (disk I/O, throttling, busy queue)
        // enough time to start sending while still cutting off truly dead peers
        // faster than eMule's full 100s.
        const INITIAL_DATA_TIMEOUT_SECS: u64 = 60;
        let mut last_epx_resend = std::time::Instant::now();
        // Use the generation we sent at handshake time as the resend
        // baseline so any rebuild that happened during file-status / queue
        // wait gets re-sent on the first periodic check. Falls back to
        // current generation when we never sent an initial EPX (peer is
        // not Ember, or our payload was empty at the time).
        let mut last_epx_generation = initial_epx_sent_generation
            .unwrap_or_else(|| ember_payload_generation.load(std::sync::atomic::Ordering::Relaxed));
        const EPX_RESEND_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

        // Receive loop. Exits when:
        //   * `peer_out_of_parts` was signalled by the remote, OR
        //   * the byte-level gap tracker reports `part_idx` complete
        //     (which is the authoritative signal for "we have every
        //     byte of this part on disk", regardless of whether the
        //     bytes came from this source's blocks for `part_idx` or
        //     from another source piling on for the same part, or
        //     from this source's pipelined blocks for part N+1
        //     overlapping nothing in part N).
        //
        // Was: `while total_received < total_sent_bytes` — broken under
        // pipelining because pipelined N+1 bytes also arrive on this
        // socket and would push `total_received` past
        // `total_sent_bytes` (which only counts current-part bytes),
        // exiting before the current part actually finishes.
        loop {
            check_control(&control).await?;
            if peer_out_of_parts {
                break;
            }
            {
                let t = tracker.read().await;
                if t.is_part_complete(part_idx) {
                    break;
                }
            }

            // Periodic EPX re-send: if payload has been rebuilt and 5min elapsed
            if hello_caps.is_ember && last_epx_resend.elapsed() >= EPX_RESEND_INTERVAL {
                let current_gen = ember_payload_generation.load(std::sync::atomic::Ordering::Relaxed);
                if current_gen != last_epx_generation {
                    let epx_data = ember_payload.read().await.clone();
                    if !epx_data.is_empty() {
                        debug!("Re-sending EPX to multi-source peer {} (gen {}->{}, {} bytes)", _src_idx, last_epx_generation, current_gen, epx_data.len());
                        let _ = write_packet_async_ms(&mut *writer, OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE, &*epx_data).await;
                        sx_overhead.record_upload((6 + epx_data.len()) as u64);
                    }
                    last_epx_generation = current_gen;
                }
                last_epx_resend = std::time::Instant::now();
            }

            // Use a shorter read timeout until we receive the first data packet.
            // Prevents waiting 100s on peers that accept but never send data.
            let read_timeout = if got_any_data {
                std::time::Duration::from_secs(super::dead_sources::DOWNLOADTIMEOUT_SECS as u64)
            } else {
                let elapsed = data_loop_start.elapsed();
                let budget = std::time::Duration::from_secs(INITIAL_DATA_TIMEOUT_SECS);
                budget.saturating_sub(elapsed).max(std::time::Duration::from_secs(1))
            };

            let (proto, opcode, payload) = match tokio::time::timeout(
                read_timeout,
                read_packet_async_ms(&mut *reader),
            ).await {
                Ok(Ok(pkt)) => {
                    if !got_any_data {
                        debug!("Source {} ({}) data loop received packet BEFORE first data: proto=0x{:02X} op=0x{:02X} ({} bytes)",
                            _src_idx, addr, pkt.0, pkt.1, pkt.2.len());
                    }
                    pkt
                },
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {
                    let _ = write_packet_async_ms(
                        &mut *writer, OP_EDONKEYHEADER, OP_CANCELTRANSFER, &[],
                    ).await;
                    if !got_any_data {
                        warn!("Source {} ({}) accepted transfer but sent no data in {}s — disconnecting",
                            _src_idx, addr, INITIAL_DATA_TIMEOUT_SECS);
                        anyhow::bail!("peer accepted transfer but sent no data in {}s", INITIAL_DATA_TIMEOUT_SECS);
                    } else {
                        anyhow::bail!("stage:data_wait download timeout: no data for {}s", super::dead_sources::DOWNLOADTIMEOUT_SECS);
                    }
                }
            };

            match (proto, opcode) {
                (OP_EMULEPROT, OP_SENDINGPART_I64) | (OP_EDONKEYHEADER, OP_SENDINGPART) => {
                    let (hash, start, end, data) = if opcode == OP_SENDINGPART_I64 {
                        parse_sending_part_i64(&payload)?
                    } else {
                        // D19: a 32-bit OP_SENDINGPART cannot address past
                        // 4 GiB. If our file is larger the peer must use
                        // OP_SENDINGPART_I64; reject 32-bit frames rather
                        // than silently wrap / mis-write.
                        if file_size > u32::MAX as u64 {
                            anyhow::bail!(
                                "source {_src_idx} sent 32-bit OP_SENDINGPART for a {}-byte file (requires I64)",
                                file_size
                            );
                        }
                        parse_sending_part_32(&payload)?
                    };
                    if hash != *file_hash {
                        anyhow::bail!(
                            "source {} sent SENDINGPART for wrong file: expected={} got={}",
                            _src_idx,
                            hex::encode(file_hash),
                            hex::encode(hash)
                        );
                    }

                    if start >= end || end > file_size || data.len() != (end - start) as usize {
                        consecutive_bad_blocks += 1;
                        tracing::warn!("Invalid block offsets from source {_src_idx}: start={start}, end={end}, data={} (bad streak: {consecutive_bad_blocks})", data.len());
                        if consecutive_bad_blocks >= MAX_CONSECUTIVE_BAD_BLOCKS {
                            anyhow::bail!("source {_src_idx} sent {consecutive_bad_blocks} consecutive invalid blocks, disconnecting");
                        }
                        continue;
                    }
                    // D18: refuse absurdly small chunks. eMule-family peers
                    // never ship OP_SENDINGPART below a few KiB; a peer
                    // sending 1-byte chunks is either broken or abusive
                    // (work amplification vs our syscall/allocator path).
                    // 16 bytes keeps the floor trivially low for any legit
                    // truncated-tail block.
                    const MIN_BLOCK_BYTES: u64 = 16;
                    let piece_len = end - start;
                    if piece_len < MIN_BLOCK_BYTES && end != file_size {
                        consecutive_bad_blocks += 1;
                        tracing::warn!(
                            "source {_src_idx} sent undersized block ({piece_len} bytes); treating as abusive"
                        );
                        if consecutive_bad_blocks >= MAX_CONSECUTIVE_BAD_BLOCKS {
                            anyhow::bail!("source {_src_idx} sent {consecutive_bad_blocks} consecutive invalid blocks, disconnecting");
                        }
                        continue;
                    }
                    consecutive_bad_blocks = 0;
                    bw.acquire_download(piece_len).await;

                    // D20: only commit the fill_range to the tracker if the
                    // disk write actually succeeded. The PartFileWriter
                    // serializes the writes for us — this `await` is just
                    // an mpsc round-trip, not a global file lock acquisition.
                    if let Err(e) = output.write(start, data.to_vec()).await {
                        tracing::warn!(
                            "source {_src_idx}: disk write failed at start={start} ({piece_len} bytes): {e}"
                        );
                        continue;
                    }

                    // Update byte-level gap tracker for mid-part resume.
                    // Only reached when the disk write succeeded.
                    {
                        let mut t = tracker.write().await;
                        t.fill_range(start, end);
                    }

                    if let (Some(ref etx), std::net::IpAddr::V4(v4)) = (&event_tx, addr.ip()) {
                        let _ = etx
                            .send(DownloadEvent::DataReceived {
                                file_hash: *file_hash,
                                start,
                                end,
                                sender_ip: v4,
                                sender_user_hash: Some(peer_user_hash),
                            })
                            .await;
                    }

                    if !got_any_data {
                        info!("Source {} ({}) first data received for part {} ({} bytes)", _src_idx, addr, part_idx, piece_len);
                        got_any_data = true;
                    }
                    src_transferred += piece_len;
                    blocks_received_in_current_req += 1;
                    speed_bytes += piece_len;
                    // D12: defer credit accrual until the covered part
                    // verifies. With cross-part pipelining a block can
                    // belong to either the current part or the
                    // pre-pipelined next part — bucket by absolute
                    // offset so a Mismatch on part N doesn't wipe
                    // legitimate part N+1 credit.
                    let block_part = (start / PARTSIZE) as usize;
                    *per_part_credit.entry(block_part).or_insert(0) += piece_len;
                    let _ = progress_tx.send((_src_idx, piece_len as i64)).await;
                }
                (OP_EMULEPROT, OP_COMPRESSEDPART_I64) | (OP_EMULEPROT, OP_COMPRESSEDPART) => {
                    let (hash, start, compressed_total_size, compressed) =
                        if opcode == OP_COMPRESSEDPART_I64 {
                            parse_compressed_part_i64(&payload)?
                        } else {
                            parse_compressed_part_32(&payload)?
                        };
                    if hash != *file_hash {
                        anyhow::bail!(
                            "source {} sent COMPRESSEDPART for wrong file: expected={} got={}",
                            _src_idx,
                            hex::encode(file_hash),
                            hex::encode(hash)
                        );
                    }

                    let Some(decompressed) = append_compressed_chunk_ms(
                        &mut pending_compressed,
                        start,
                        compressed_total_size,
                        compressed,
                    )? else {
                        continue;
                    };

                    let piece_len = decompressed.len() as u64;
                    if start.saturating_add(piece_len) > file_size {
                        consecutive_bad_blocks += 1;
                        tracing::warn!("Compressed block exceeds file size from source {_src_idx} (bad streak: {consecutive_bad_blocks})");
                        if consecutive_bad_blocks >= MAX_CONSECUTIVE_BAD_BLOCKS {
                            anyhow::bail!("source {_src_idx} sent {consecutive_bad_blocks} consecutive invalid blocks, disconnecting");
                        }
                        continue;
                    }
                    consecutive_bad_blocks = 0;
                    bw.acquire_download(piece_len).await;

                    if let Err(e) = output.write(start, decompressed).await {
                        tracing::warn!(
                            "source {_src_idx}: compressed disk write failed at start={start} ({piece_len} bytes): {e}"
                        );
                        continue;
                    }

                    {
                        let mut t = tracker.write().await;
                        t.fill_range(start, start + piece_len);
                    }

                    if let (Some(ref etx), std::net::IpAddr::V4(v4)) = (&event_tx, addr.ip()) {
                        let _ = etx
                            .send(DownloadEvent::DataReceived {
                                file_hash: *file_hash,
                                start,
                                end: start + piece_len,
                                sender_ip: v4,
                                sender_user_hash: Some(peer_user_hash),
                            })
                            .await;
                    }

                    if !got_any_data {
                        info!("Source {} ({}) first compressed data received for part {} ({} bytes)", _src_idx, addr, part_idx, piece_len);
                        got_any_data = true;
                    }
                    src_transferred += piece_len;
                    blocks_received_in_current_req += 1;
                    speed_bytes += piece_len;
                    // Per-part credit bucket; see uncompressed branch
                    // above for rationale.
                    let block_part = (start / PARTSIZE) as usize;
                    *per_part_credit.entry(block_part).or_insert(0) += piece_len;
                    let _ = progress_tx.send((_src_idx, piece_len as i64)).await;
                }
                (OP_EMULEPROT, OP_AICHANSWER) if payload.len() >= 38 => {
                    let mut ans_hash = [0u8; 16];
                    ans_hash.copy_from_slice(&payload[..16]);
                    let ans_part = u16::from_le_bytes([payload[16], payload[17]]) as usize;
                    let mut root_hash = [0u8; 20];
                    root_hash.copy_from_slice(&payload[18..38]);
                    let recovery_data = &payload[38..];
                    if ans_hash == *file_hash && ans_part == part_idx {
                        let aich_master_hash = *shared_aich_master.read().await;
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
                (OP_EDONKEYHEADER, OP_OUTOFPARTREQS) => {
                    peer_out_of_parts = true;
                    break;
                }
                // Peer revoked our upload slot mid-transfer (queue recalculation).
                // OP_QUEUEFULL (0x93) shares its opcode with OP_MULTIPACKETANSWER;
                // QueueFull always has an empty payload.
                (OP_EMULEPROT, OP_QUEUEFULL) if payload.is_empty() => {
                    emit_source!("queue_full", None, measured_speed);
                    anyhow::bail!("peer revoked upload slot (QueueFull during transfer)");
                }
                (OP_EMULEPROT, OP_QUEUERANKING) if payload.len() >= 2 => {
                    let rank = u16::from_le_bytes([payload[0], payload[1]]);
                    emit_source!("queued", Some(rank as u32), measured_speed);
                    anyhow::bail!("peer put us back in queue at rank {} during transfer", rank);
                }
                (OP_EDONKEYHEADER, OP_QUEUERANK) if payload.len() >= 4 => {
                    let rank = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    emit_source!("queued", Some(rank), measured_speed);
                    anyhow::bail!("peer put us back in queue at rank {} during transfer", rank);
                }
                (OP_EDONKEYHEADER, OP_FILEREQANSNOFIL) => {
                    anyhow::bail!("peer no longer has the file (FileNotFound during transfer)");
                }
                // Source exchange response: register discovered sources and
                // notify the network loop so they can be injected into the
                // active download immediately.
                (OP_EMULEPROT, OP_ANSWERSOURCES) if payload.len() >= 18 => {
                    sx_overhead.record_download((6 + payload.len()) as u64);
                    match parse_answer_sources(&payload, peer_source_exchange_ver) {
                        Ok((version, answer_hash, entries)) if answer_hash == *file_hash => {
                            let mut sx_count = 0u32;
                            let mut sx_entries: Vec<super::transfer::SourceExchangeEntry> = Vec::new();
                            for entry in entries {
                                if entry.tcp_port == 0 {
                                    continue;
                                }
                                if entry.source_id < 16_777_216 {
                                    debug!("SX1: skipping Low-ID source {} (server {:08X}:{})", entry.source_id, entry.server_ip, entry.server_port);
                                    continue;
                                }
                                let ip = source_exchange_id_to_ipv4(version, entry.source_id);
                                if is_filtered_source_ip(&ip) || is_sx_rejected(&ip, entry.tcp_port) {
                                    continue;
                                }
                                let uh = entry.user_hash.unwrap_or([0u8; 16]);
                                let co = entry.crypt_options.unwrap_or(0);
                                if let Some(sm) = &source_mgr {
                                    let mut sm = sm.write().await;
                                    sm.register_source_full_server(
                                        *file_hash, ip, entry.tcp_port, 0, entry.server_ip, entry.server_port, uh, co,
                                    );
                                }
                                sx_entries.push(super::transfer::SourceExchangeEntry {
                                    ip, tcp_port: entry.tcp_port, user_hash: uh, crypt_options: co,
                                });
                                sx_count += 1;
                            }
                            if sx_count > 0 {
                                debug!(
                                    "Legacy source exchange: registered {sx_count} new sources from multi-source peer {}",
                                    _src_idx
                                );
                                if let Some(ref etx) = event_tx {
                                    let _ = etx.send(DownloadEvent::SourceExchange {
                                        transfer_id: transfer_id.clone(),
                                        file_hash: *file_hash,
                                        sources: sx_entries,
                                    }).await;
                                }
                            }
                        }
                        Ok((_version, answer_hash, _)) => {
                            debug!(
                                "Ignoring OP_ANSWERSOURCES from multi-source peer {} for different file {}",
                                _src_idx,
                                hex::encode(answer_hash)
                            );
                        }
                        Err(e) => debug!("Failed to parse OP_ANSWERSOURCES from multi-source peer {}: {e}", _src_idx),
                    }
                }
                (OP_EMULEPROT, OP_ANSWERSOURCES2) if payload.len() >= 19 => {
                    sx_overhead.record_download((6 + payload.len()) as u64);
                    match parse_answer_sources2(&payload) {
                        Ok((version, answer_hash, entries)) if answer_hash == *file_hash => {
                            let mut sx_count = 0u32;
                            let mut sx_entries: Vec<super::transfer::SourceExchangeEntry> = Vec::new();
                            for entry in entries {
                                if entry.tcp_port == 0 {
                                    continue;
                                }
                                if entry.source_id < 16_777_216 {
                                    debug!("SX2: skipping Low-ID source {} (server {:08X}:{})", entry.source_id, entry.server_ip, entry.server_port);
                                    continue;
                                }
                                let ip = source_exchange_id_to_ipv4(version, entry.source_id);
                                if is_filtered_source_ip(&ip) || is_sx_rejected(&ip, entry.tcp_port) {
                                    continue;
                                }
                                if entry.server_ip != 0 {
                                    debug!("SX2 source {} advertises server {:08X}:{}", ip, entry.server_ip, entry.server_port);
                                }
                                let uh = entry.user_hash.unwrap_or([0u8; 16]);
                                let co = entry.crypt_options.unwrap_or(0);
                                if let Some(sm) = &source_mgr {
                                    let mut sm = sm.write().await;
                                    sm.register_source_full_server(
                                        *file_hash, ip, entry.tcp_port, 0,
                                        entry.server_ip, entry.server_port, uh, co,
                                    );
                                }
                                sx_entries.push(super::transfer::SourceExchangeEntry {
                                    ip, tcp_port: entry.tcp_port, user_hash: uh, crypt_options: co,
                                });
                                sx_count += 1;
                            }
                            if sx_count > 0 {
                                debug!("Source exchange: registered {sx_count} new sources from multi-source peer {}", _src_idx);
                                if let Some(ref etx) = event_tx {
                                    let _ = etx.send(DownloadEvent::SourceExchange {
                                        transfer_id: transfer_id.clone(),
                                        file_hash: *file_hash,
                                        sources: sx_entries,
                                    }).await;
                                }
                            }
                        }
                        Ok((_version, answer_hash, _)) => {
                            debug!(
                                "Ignoring OP_ANSWERSOURCES2 from multi-source peer {} for different file {}",
                                _src_idx,
                                hex::encode(answer_hash)
                            );
                        }
                        Err(e) => debug!("Failed to parse OP_ANSWERSOURCES2 from multi-source peer {}: {e}", _src_idx),
                    }
                }
                (OP_EMULEPROT, OP_EMBER_SOURCEEXCHANGE) => {
                    sx_overhead.record_download((6 + payload.len()) as u64);
                    if epx_packets_received >= crate::network::ember::MAX_EPX_PACKETS_PER_CONNECTION {
                        debug!("Ignoring excess EPX packet from multi-source peer {}", _src_idx);
                    } else {
                        epx_packets_received += 1;
                        match crate::network::ember::parse_exchange_payload(&payload) {
                            Ok(result) if !result.files.is_empty() || !result.peers.is_empty() => {
                                info!("Received Ember Peer Exchange from multi-source peer {} ({} files, {} peers)", _src_idx, result.files.len(), result.peers.len());
                                let (epx_entries, aich_roots) = super::transfer::epx_result_to_entries(&result);
                                let ember_peers = result.peers.into_iter().map(|p| (p.ip, p.tcp_port)).collect();
                                if let Some(ref etx) = event_tx {
                                    let _ = etx.send(DownloadEvent::EmberSources {
                                        transfer_id: transfer_id.clone(),
                                        entries: epx_entries,
                                        aich_roots,
                                        ember_peers,
                                    }).await;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => debug!("Failed to parse Ember exchange from peer {}: {e}", _src_idx),
                        }
                    }
                }
                (OP_EMULEPROT, OP_EMBER_FRIEND_REQ) if hello_caps.is_ember => {
                    if let (Some(eh), Some(ref etx)) = (peer_ember_hash, &event_tx) {
                        let nick = std::str::from_utf8(&payload).unwrap_or("").to_string();
                        let _ = etx.send(DownloadEvent::EmberFriendRequest {
                            ember_hash: eh,
                            nickname: nick,
                            peer_ip: addr.ip().to_string(),
                            peer_port: addr.port(),
                        }).await;
                    }
                }
                (OP_EMULEPROT, OP_EMBER_CHAT_MSG) if is_ember_friend && payload.len() <= 4096 => {
                    if let (Some(eh), Some(ref etx)) = (peer_ember_hash, &event_tx) {
                        if let Ok(msg) = std::str::from_utf8(&payload) {
                            let _ = etx.send(DownloadEvent::EmberChatMessage {
                                ember_hash: eh,
                                message: msg.to_string(),
                            }).await;
                        }
                    }
                }
                (OP_EMULEPROT, OP_EMBER_BROWSE_RES) if is_ember_friend => {
                    if let (Some(eh), Some(ref etx)) = (peer_ember_hash, &event_tx) {
                        let entries = parse_browse_response(&payload);
                        let _ = etx.send(DownloadEvent::EmberBrowseResponse {
                            ember_hash: eh,
                            entries,
                        }).await;
                    }
                }
                (OP_EMULEPROT, OP_FILEDESC) if payload.len() >= 5 => {
                    let rating = payload[0];
                    let comment_len = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
                    if comment_len.checked_add(5).map_or(false, |need| payload.len() >= need) {
                        let comment = String::from_utf8_lossy(&payload[5..5+comment_len]).to_string();
                        if let Some(cm) = &comment_mgr {
                            let mut cm = cm.write().await;
                            cm.add_peer_comment(
                                &hex::encode(file_hash),
                                addr.to_string(),
                                rating,
                                comment.clone(),
                                0,
                            );
                        }
                        debug!("Peer comment from source {}: rating={rating}, comment='{comment}'", _src_idx);
                    }
                }
                _ => {
                    info!("During data transfer, unexpected packet proto=0x{:02X} op=0x{:02X} ({} bytes) from source {} ({})",
                        proto, opcode, payload.len(), _src_idx, addr);
                }
            }

            // Pipeline refill when a request's worth of blocks completes
            let blocks_in_batch = if completed_reqs < batches.len() {
                batches[completed_reqs].len()
            } else {
                MAX_BLOCKS_PER_REQUEST
            };
            if blocks_received_in_current_req >= blocks_in_batch {
                blocks_received_in_current_req = 0;
                completed_reqs += 1;
                if sent_idx < batches.len() {
                    let batch = &batches[sent_idx];
                    let (req_payload, req_proto, req_op) = if needs_i64 {
                        (build_request_parts_i64(file_hash, batch), OP_EMULEPROT, OP_REQUESTPARTS_I64)
                    } else {
                        (build_request_parts(file_hash, batch), OP_EDONKEYHEADER, OP_REQUESTPARTS)
                    };
                    write_packet_async_ms(&mut *writer, req_proto, req_op, &req_payload).await?;
                    sent_idx += 1;
                } else if pipelined_next.is_none() && !batches.is_empty() {
                    // CROSS-PART PIPELINE: every batch for the current
                    // part has been sent, but we're still receiving
                    // bytes. Pre-pick the next part and ship its first
                    // OP_REQUESTPARTS so the peer's send queue stays
                    // saturated through the part-N → part-(N+1)
                    // hand-off (no round-trip stall, no Hello/SecIdent
                    // reconnect).
                    if let Some(next) = pre_pipeline_next_part_ms(
                        &chunk_sel,
                        &tracker,
                        &source_available,
                        &control,
                        &part_queue,
                        peer_supports_large_files,
                        file_size,
                    )
                    .await
                    {
                        let first_batch = &next.batches[0];
                        let (req_payload, req_proto, req_op) = if next.needs_i64 {
                            (build_request_parts_i64(file_hash, first_batch), OP_EMULEPROT, OP_REQUESTPARTS_I64)
                        } else {
                            (build_request_parts(file_hash, first_batch), OP_EDONKEYHEADER, OP_REQUESTPARTS)
                        };
                        if let Err(e) = write_packet_async_ms(&mut *writer, req_proto, req_op, &req_payload).await {
                            // Don't poison the rest of the loop on a
                            // pipeline-send failure — fall through and
                            // let the existing per-part flow handle the
                            // next part on its own (with the round-trip
                            // stall, but not a session drop).
                            debug!(
                                "Source {} ({}) cross-part pipeline send for part {} failed: {e:#} — falling back to non-pipelined hand-off",
                                _src_idx, addr, next.part_idx,
                            );
                        } else {
                            let pipelined_bytes: u64 =
                                first_batch.iter().map(|(s, e)| e - s).sum();
                            debug!(
                                "Source {} ({}) cross-part pipeline: pre-sent first batch of part {} ({} bytes) while still receiving part {}",
                                _src_idx, addr, next.part_idx, pipelined_bytes, part_idx,
                            );
                            // Add to part_queue if not already present;
                            // mark in_progress so other sources see it
                            // and apply the eMule active-bonus heuristic.
                            if !part_queue.contains(&next.part_idx) {
                                part_queue.push(next.part_idx);
                            }
                            {
                                let mut t = tracker.write().await;
                                t.set_in_progress(next.part_idx, true);
                            }
                            ip_guard.mark(next.part_idx);
                            let _ = pipelined_bytes;
                            pipelined_next = Some(PipelinedNext {
                                part_idx: next.part_idx,
                                all_blocks: next.all_blocks,
                                batches: next.batches,
                                sent_idx: 1,
                                needs_i64: next.needs_i64,
                            });
                        }
                    }
                }
            }

            let elapsed = speed_start.elapsed();
            if elapsed.as_millis() >= 2000 {
                measured_speed =
                    (speed_bytes as u128 * 1000 / elapsed.as_millis().max(1)) as u64;
                speed_bytes = 0;
                speed_start = std::time::Instant::now();
                emit_source!("transferring", None, measured_speed);
            }

            if last_periodic_save.elapsed() >= PERIODIC_SAVE_INTERVAL {
                // CRITICAL: take the snapshot under the lock, then drop the
                // lock BEFORE the disk write. Previously this held
                // `tracker.read().await` across `atomic_write+fsync` —
                // which blocked every writer trying to call `fill_range`
                // for the duration of the fsync.
                let snap = {
                    let t = tracker.read().await;
                    t.snapshot_for_save()
                };
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = snap.write_to_disk() {
                        tracing::warn!("periodic part.met save failed: {e}");
                    }
                });
                last_periodic_save = std::time::Instant::now();
            }
        }

        // No pre-verification fsync: the writer thread reads from the same
        // open file handle it wrote with, so the OS page cache is
        // self-consistent. Skipping fsync here removes a per-part disk
        // round-trip (tens of ms on HDDs / network shares) without
        // affecting correctness — the final fsync still runs at completion.

        if peer_out_of_parts {
            let snap = {
                let mut t = tracker.write().await;
                t.set_in_progress(part_idx, false);
                t.snapshot_for_save()
            };
            spawn_save_snapshot(snap);
            ip_guard.unmark(part_idx);
            continue;
        }

        // Guard against duplicate/overlapping blocks that satisfied the
        // byte budget without actually closing all gaps in this part.
        {
            let t = tracker.read().await;
            let (ps, pe) = t.part_range(part_idx);
            let part_has_gaps = t.gap_list().iter().any(|&(gs, ge)| gs < pe && ge > ps);
            if part_has_gaps {
                warn!(
                    "Source {} part {} byte budget met but gaps remain — peer likely sent duplicate blocks, marking for retry",
                    _src_idx, part_idx
                );
                drop(t);
                let snap = {
                    let mut t = tracker.write().await;
                    t.set_in_progress(part_idx, false);
                    t.snapshot_for_save()
                };
                spawn_save_snapshot(snap);
                ip_guard.unmark(part_idx);
                continue;
            }
        }

        // Verify part hash before marking complete
        let part_hash_outcome = {
            let ph = shared_part_hashes.read().await;
            if part_idx < ph.len() {
                let expected_hash = ph[part_idx];
                let t = tracker.read().await;
                let (ps, pe) = t.part_range(part_idx);
                let part_len = (pe - ps) as usize;
                drop(t);

                // Read + MD4 in one writer-thread round-trip: the hash
                // never runs on an async worker, and there's no second
                // file-lock acquisition (the writer thread serializes us
                // anyway).
                let (part_data, actual_hash) = output
                    .hash_part_md4(ps, part_len)
                    .await
                    .map_err(|e| anyhow::anyhow!("part hash read at {ps}: {e}"))?;

                if actual_hash != expected_hash {
                    let aich_hs = super::aich::AICHRecoveryHashSet::build_from_data(&part_data);
                    warn!(
                        "Multi-source part {} hash mismatch from source {}! expected={} got={}, part_aich_root={}, {} AICH leaves",
                        part_idx,
                        _src_idx,
                        hex::encode(expected_hash),
                        hex::encode(actual_hash),
                        hex::encode(aich_hs.root_hash),
                        aich_hs.leaf_count(),
                    );

                    let mut recovery_bytes: Option<Vec<u8>> = aich_recovery_data
                        .as_ref()
                        .map(|(_, d)| d.clone());
                    let master_opt = *shared_aich_master.read().await;
                    if let Some(master_hash) = master_opt {
                        if recovery_bytes.is_none() && peer_supports_aich {
                            let aich_should_try = if let std::net::IpAddr::V4(v4) = addr.ip() {
                                if let Some(ref pending) = aich_pending {
                                    if let Ok(map) = pending.read() {
                                        match map.get(&(*file_hash, part_idx as u32)) {
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
                                aich_req.extend_from_slice(file_hash);
                                aich_req.extend_from_slice(&(part_idx as u16).to_le_bytes());
                                aich_req.extend_from_slice(&master_hash);
                                if let Err(e) = write_packet_async_ms(
                                    &mut *writer,
                                    OP_EMULEPROT,
                                    OP_AICHREQUEST,
                                    &aich_req,
                                )
                                .await
                                {
                                    warn!("Failed to send OP_AICHREQUEST: {e}");
                                } else {
                                    debug!("Sent OP_AICHREQUEST for part {part_idx}, waiting for answer");
                                    recovery_bytes = wait_for_aich_recovery_answer_ms(
                                        &mut *reader,
                                        file_hash,
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
                                file_size,
                            ) {
                                if !corrupt.is_empty() {
                                    let mut invalidated = 0u64;
                                    let snap = {
                                        let mut t = tracker.write().await;
                                        for &bi in &corrupt {
                                            let rel = bi as u64 * super::aich::AICH_BLOCK_SIZE as u64;
                                            let gs = ps + rel;
                                            let ge = (gs + super::aich::AICH_BLOCK_SIZE as u64)
                                                .min(ps + part_len as u64);
                                            t.invalidate_range(gs, ge);
                                            invalidated += ge - gs;
                                        }
                                        t.snapshot_for_save()
                                    };
                                    spawn_save_snapshot(snap);
                                    let _ = progress_tx
                                        .send((_src_idx, -(invalidated as i64)))
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

                        if narrowed {
                            PartHashOutcome::AichNarrowed
                        } else {
                            if let std::net::IpAddr::V4(v4) = addr.ip() {
                                if let Some(ref etx) = event_tx {
                                    let _ = etx
                                        .send(DownloadEvent::AichRecoveryFailed {
                                            file_hash: *file_hash,
                                            part_index: part_idx as u32,
                                            failed_ip: v4,
                                        })
                                        .await;
                                }
                            }
                            // D15: subtract only the bytes for THIS part,
                            // not the whole session total. Subtracting
                            // total_received over-rewinds progress and
                            // breaks stall detection.
                            let _ = progress_tx
                                .send((_src_idx, -(part_len as i64)))
                                .await;
                            PartHashOutcome::Mismatch
                        }
                    } else {
                        let _ = progress_tx
                            .send((_src_idx, -(part_len as i64)))
                            .await;
                        PartHashOutcome::Mismatch
                    }
                } else {
                    debug!("Multi-source part {} hash verified OK (source {})", part_idx, _src_idx);
                    PartHashOutcome::Verified
                }
            } else {
                PartHashOutcome::Unverified
            }
        };

        match part_hash_outcome {
            PartHashOutcome::AichNarrowed => {
                let snap = {
                    let mut t = tracker.write().await;
                    t.set_in_progress(part_idx, false);
                    t.snapshot_for_save()
                };
                spawn_save_snapshot(snap);
                ip_guard.unmark(part_idx);
                continue;
            }
            PartHashOutcome::Verified => {
                let (ps, pe, snap) = {
                    let mut t = tracker.write().await;
                    let (ps, pe) = t.part_range(part_idx);
                    t.mark_complete(part_idx);
                    // Flip the persistent verified flag so the upload path
                    // can serve this range (see is_range_safe_to_serve).
                    t.set_part_verified(part_idx);
                    t.set_in_progress(part_idx, false);
                    (ps, pe, t.snapshot_for_save())
                };
                spawn_save_snapshot(snap);
                ip_guard.unmark(part_idx);
                // D12: flush accumulated bytes to the credit ledger now
                // that this peer's contribution went into a verified part.
                // Per-part bucket: only credit bytes that landed in
                // THIS verified part. With cross-part pipelining the
                // pending map may also hold bytes for part N+1 that
                // are still in flight; those stay until N+1 verifies.
                if let Some(verified_bytes) = per_part_credit.remove(&part_idx) {
                    if verified_bytes > 0 {
                        if let Some(cm) = &credit_mgr {
                            let mut cm = cm.write().await;
                            cm.add_downloaded(peer_user_hash, verified_bytes);
                        }
                    }
                }
                if let Some(ref etx) = event_tx {
                    let _ = etx
                        .send(DownloadEvent::PartVerified {
                            file_hash: *file_hash,
                            part_start: ps,
                            part_end: pe,
                            sender_user_hash: Some(peer_user_hash),
                        })
                        .await;
                }
            }
            PartHashOutcome::Mismatch => {
                let (ps, pe, snap) = {
                    let mut t = tracker.write().await;
                    let (ps, pe) = t.part_range(part_idx);
                    // D15: the inner verification block has already sent a
                    // progress correction for this part (using part_len);
                    // don't double-subtract here.
                    t.mark_incomplete(part_idx);
                    t.set_in_progress(part_idx, false);
                    (ps, pe, t.snapshot_for_save())
                };
                spawn_save_snapshot(snap);
                ip_guard.unmark(part_idx);
                // D12: drop the per-part credit bucket for THIS part —
                // the peer sent data that didn't verify, so no credit
                // accrues for this part. With cross-part pipelining
                // we leave other parts' buckets intact (they verify
                // independently).
                per_part_credit.remove(&part_idx);
                let _ = progress_tx.send((_src_idx, 0i64)).await;
                if let Some(ref etx) = event_tx {
                    let _ = etx
                        .send(DownloadEvent::PartCorrupted {
                            file_hash: *file_hash,
                            part_start: ps,
                            part_end: pe,
                            sender_user_hash: Some(peer_user_hash),
                        })
                        .await;
                }
            }
            PartHashOutcome::Unverified => {
                let snap = {
                    let mut t = tracker.write().await;
                    t.set_in_progress(part_idx, false);
                    t.snapshot_for_save()
                };
                spawn_save_snapshot(snap);
                ip_guard.unmark(part_idx);
            }
        }

        // Dynamically select the next part if we have a shared chunk selector.
        //
        // CRITICAL: keep the TCP session alive across multiple parts. If
        // we can't find a fresh part this loop iteration the source
        // disconnects and we have to redo the full Hello/SecIdent
        // handshake (and the peer's `FILEREASKTIME` may force us to
        // wait minutes before they accept us again — visibly: "DONE,
        // speed → 0, reconnect, next part").
        //
        // Two-stage selection:
        //   1. Strict: pick a part that NO source is currently
        //      downloading (rarest-first, anti-herding). This is the
        //      preferred outcome.
        //   2. Fallback: if every remaining incomplete part is already
        //      in_progress on some other source, pile onto one of them.
        //      This is `MAX_SOURCES_PER_PART`-style behaviour matching
        //      the initial-assignment phase (which already allows up to
        //      5 sources per part). The byte-level gap tracker stops
        //      duplicate writes — source B will request only the still-
        //      empty ranges of part X via `tracker.gap_list()`, so the
        //      wasted-bandwidth cost is bounded to the blocks in flight
        //      at the exact moment of the request.
        if let Some(cs) = &chunk_sel {
            let cs = cs.read().await;
            let t = tracker.read().await;
            let completed = t.completed_parts().to_vec();
            let in_prog = t.in_progress.clone();
            let remaining = t.remaining_count();
            let part_count = t.part_count;
            let gap_bytes = t.part_gap_bytes_vec();
            drop(t);
            if remaining == 0 {
                break;
            }
            let avail = if source_available.is_empty() {
                vec![true; part_count]
            } else {
                source_available.clone()
            };
            let pp = control.is_preview_priority();
            let prefer_higher = remaining <= 3 && part_count > 1;
            let active: Vec<usize> = in_prog.iter().enumerate()
                .filter(|(_, &ip)| ip).map(|(i, _)| i).collect();
            let next_part = cs
                .select_part(&completed, &in_prog, &avail, &active, &gap_bytes, pp, prefer_higher)
                .or_else(|| {
                    // Fallback: relaxed selection. Treat no part as
                    // in-progress so we can piggy-back on one another
                    // source is already pulling. `active_parts` is
                    // still the real active list, so the
                    // active-chunk-bonus (lower score) inside
                    // select_part will prefer joining a part already
                    // in motion over starting a fresh in-progress
                    // one — that's also what the eMule endgame mode
                    // does naturally.
                    let no_in_progress = vec![false; part_count];
                    cs.select_part(
                        &completed,
                        &no_in_progress,
                        &avail,
                        &active,
                        &gap_bytes,
                        pp,
                        prefer_higher,
                    )
                });
            if let Some(next) = next_part {
                if !part_queue.contains(&next) {
                    part_queue.push(next);
                    // Mark in_progress (idempotent — may already be
                    // set by another source). `ip_guard.mark` records
                    // that THIS source contributed to this part so
                    // teardown unmarks correctly even when another
                    // source also claimed it.
                    let mut t = tracker.write().await;
                    t.set_in_progress(next, true);
                    drop(t);
                    ip_guard.mark(next);
                }
            } else {
                // No remaining part is reachable from this source
                // (the peer's `available_parts` doesn't intersect the
                // not-yet-complete set). Genuinely nothing left to do
                // here — let the loop fall through to the natural
                // `OP_END_OF_DOWNLOAD` exit.
                debug!(
                    "Source {} ({}): no overlap between peer's part availability and remaining incomplete parts; ending session cleanly",
                    _src_idx, addr
                );
            }
        }
    }

    // Signal the uploader that we're done
    write_packet_async_ms(
        &mut *writer,
        OP_EDONKEYHEADER,
        OP_END_OF_DOWNLOAD,
        &[],
    )
    .await
    .ok();

    emit_source!("completed", None, measured_speed);

    // Decrement wire-learned availability now that this source is done.
    // Sources with pre-existing availability are decremented by the spawning
    // closure instead.
    if let Some(ref avail) = wire_counted_avail {
        if let Some(cs) = &chunk_sel {
            let mut cs = cs.write().await;
            cs.remove_source(avail);
        }
    }

    Ok(())
}

/// Pre-computed pipeline state for the next part this source should
/// download, so the receive loop can ship its first OP_REQUESTPARTS
/// without yet allocating for the rest of the batches' send budget.
struct PipelineCandidate {
    part_idx: usize,
    all_blocks: Vec<(u64, u64)>,
    batches: Vec<Vec<(u64, u64)>>,
    needs_i64: bool,
}

/// Pick the next part to pre-pipeline for this source, applying the
/// same two-stage selection (strict, then relaxed) as the post-part
/// dynamic-extend path. Returns `None` when there's nothing useful to
/// pipeline (every remaining part either falls outside the peer's
/// availability map, is already pipelined / queued for this source,
/// or has no gaps left).
async fn pre_pipeline_next_part_ms(
    chunk_sel: &Option<Arc<RwLock<ChunkSelector>>>,
    tracker: &Arc<RwLock<PartTracker>>,
    source_available: &[bool],
    control: &Arc<TransferControl>,
    part_queue: &[usize],
    peer_supports_large_files: bool,
    file_size: u64,
) -> Option<PipelineCandidate> {
    let cs = chunk_sel.as_ref()?.read().await;

    let (completed, in_prog, remaining, part_count, gap_bytes) = {
        let t = tracker.read().await;
        (
            t.completed_parts().to_vec(),
            t.in_progress.clone(),
            t.remaining_count(),
            t.part_count,
            t.part_gap_bytes_vec(),
        )
    };
    if remaining == 0 {
        return None;
    }
    let avail = if source_available.is_empty() {
        vec![true; part_count]
    } else {
        source_available.to_vec()
    };
    let pp = control.is_preview_priority();
    let prefer_higher = remaining <= 3 && part_count > 1;
    let active: Vec<usize> = in_prog
        .iter()
        .enumerate()
        .filter(|(_, &ip)| ip)
        .map(|(i, _)| i)
        .collect();

    // Strict: pick a part nobody is currently downloading.
    let mut next_part = cs.select_part(
        &completed,
        &in_prog,
        &avail,
        &active,
        &gap_bytes,
        pp,
        prefer_higher,
    );
    // Relaxed fallback (matches the post-verify dynamic-extend logic):
    // every remaining incomplete part is already in_progress on some
    // source — pile on, with the active-bonus naturally preferring
    // already-active parts.
    if next_part.is_none() {
        let no_in_progress = vec![false; part_count];
        next_part = cs.select_part(
            &completed,
            &no_in_progress,
            &avail,
            &active,
            &gap_bytes,
            pp,
            prefer_higher,
        );
    }
    let next_part = next_part?;

    // Don't double-pipeline a part already in this source's queue.
    if part_queue.contains(&next_part) {
        return None;
    }

    let (all_blocks, _ps, _pe) = compute_part_blocks_ms(tracker, next_part).await;
    if all_blocks.is_empty() {
        // Race: another source filled the part between select_part and
        // now. Caller can re-try on the next iteration.
        return None;
    }
    let batches: Vec<Vec<(u64, u64)>> = all_blocks
        .chunks(MAX_BLOCKS_PER_REQUEST)
        .map(|c| c.to_vec())
        .collect();
    if batches.is_empty() {
        return None;
    }
    let needs_i64 =
        peer_supports_large_files && all_blocks.iter().any(|&(_, end)| end > u32::MAX as u64);
    let _ = file_size;

    Some(PipelineCandidate {
        part_idx: next_part,
        all_blocks,
        batches,
        needs_i64,
    })
}

/// Compute the gap-aware OP_REQUESTPARTS block list for `part_idx`.
/// Returns (`all_blocks`, `part_start`, `part_end`). Splits each
/// in-part gap into EMBLOCKSIZE chunks (eMule's request granularity).
/// Used by both the cold path at the top of the per-part loop and the
/// pipeline send-ahead.
async fn compute_part_blocks_ms(
    tracker: &Arc<RwLock<PartTracker>>,
    part_idx: usize,
) -> (Vec<(u64, u64)>, u64, u64) {
    use super::messages::EMBLOCKSIZE;
    let t = tracker.read().await;
    let (part_start, part_end) = t.part_range(part_idx);
    let all_blocks: Vec<(u64, u64)> = t
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
    (all_blocks, part_start, part_end)
}

fn outstanding_requests_for_speed_ms(
    speed: u64,
    remaining_parts: usize,
    remaining_gap_bytes: u64,
) -> usize {
    use super::messages::PARTSIZE;
    // eMule block counts per speed tier (DownloadClient.cpp:804-810),
    // extended with higher tiers for modern broadband connections.
    //
    // Cold-start treatment: the measurement window updates every 2 seconds
    // (see `speed_start.elapsed().as_millis() >= 2000` in the download
    // loop), so at `speed == 0` we'd otherwise sit at the lowest-tier
    // pipeline depth for the entire first window. On a high-bandwidth
    // peer that's a multi-second underutilisation: at 10 MB/s, 1 packet
    // (540 KiB of blocks) fills ~50 ms, after which the peer's upload
    // pipeline stalls waiting for our refill. Treat the unknown-speed
    // case as if we were already in the mid 75 KiB/s tier — 6 blocks
    // outstanding, which rounds to 2 OP_REQUESTPARTS packets. Still
    // compatible with stock eMule: `AddReqBlock` (UploadClient.cpp:320+)
    // has no hard queue cap, and their `StartCreateNextBlockPackage`
    // BIGBUFFER limit of 900 KiB naturally absorbs up to 5 blocks before
    // back-pressuring disk reads.
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
    } else if speed == 0 {
        6
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

/// Wait for `OP_AICHANSWER` matching file, part, and trusted AICH master hash (up to ~8s).
async fn wait_for_aich_recovery_answer_ms<R: AsyncReadExt + Unpin + ?Sized>(
    reader: &mut R,
    file_hash: &[u8; 16],
    part_idx: usize,
    expected_master: [u8; 20],
) -> Option<Vec<u8>> {
    use super::messages::{OP_AICHANSWER, OP_EMULEPROT};

    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(8);
    let deadline = tokio::time::Instant::now() + MAX_WAIT;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let chunk = remaining.min(std::time::Duration::from_secs(2));
        match tokio::time::timeout(chunk, read_packet_async_ms(reader)).await {
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

async fn read_packet_timeout_ms<R: AsyncReadExt + Unpin + ?Sized>(
    reader: &mut R,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    tokio::time::timeout(
        std::time::Duration::from_secs(super::dead_sources::DOWNLOADTIMEOUT_SECS as u64),
        read_packet_async_ms(reader),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timed out"))?
}

async fn read_packet_async_ms<R: AsyncReadExt + Unpin + ?Sized>(
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
        use std::io::Read;
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
        return Ok((super::messages::OP_EMULEPROT, opcode, unpacked));
    }
    Ok((protocol, opcode, payload))
}

fn decompress_ed2k_part_ms(compressed: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let zlib_result = {
        let mut decoder = ZlibDecoder::new(compressed);
        let mut decompressed = Vec::new();
        let mut buf = [0u8; 8192];
        (|| -> anyhow::Result<Vec<u8>> {
            loop {
                let n = decoder.read(&mut buf)?;
                if n == 0 { break; }
                decompressed.extend_from_slice(&buf[..n]);
                if decompressed.len() > MAX_DECOMPRESSED_PART {
                    anyhow::bail!("decompressed part exceeds size limit");
                }
            }
            Ok(decompressed)
        })()
    };
    if let Ok(data) = zlib_result {
        return Ok(data);
    }
    let mut decoder = DeflateDecoder::new(compressed);
    let mut decompressed = Vec::new();
    let mut buf = [0u8; 8192];
    let deflate_result: anyhow::Result<Vec<u8>> = (|| {
        loop {
            let n = decoder.read(&mut buf)?;
            if n == 0 { break; }
            decompressed.extend_from_slice(&buf[..n]);
            if decompressed.len() > MAX_DECOMPRESSED_PART {
                anyhow::bail!("decompressed part exceeds size limit");
            }
        }
        Ok(decompressed)
    })();
    if let Ok(data) = deflate_result {
        return Ok(data);
    }
    Err(zlib_result.unwrap_err())
}

async fn write_packet_async_ms<W: AsyncWriteExt + Unpin + ?Sized>(
    writer: &mut W,
    protocol: u8,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let pkt_len = u32::try_from(1 + payload.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "packet payload too large"))?;
    writer.write_u8(protocol).await?;
    writer.write_u32_le(pkt_len).await?;
    writer.write_u8(opcode).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injection_wait_breaks_when_channel_is_closed() {
        assert_eq!(
            injection_wait_action(true, false, false, false),
            InjectionWaitAction::Break,
        );
    }

    #[test]
    fn injection_wait_starts_deadline_once_sources_finish() {
        assert_eq!(
            injection_wait_action(true, true, false, false),
            InjectionWaitAction::StartDeadline,
        );
        assert_eq!(
            injection_wait_action(true, true, true, false),
            InjectionWaitAction::Continue,
        );
        assert_eq!(
            injection_wait_action(true, true, true, true),
            InjectionWaitAction::Break,
        );
    }

    /// Cold-start (speed == 0) must issue at least 2 concurrent
    /// OP_REQUESTPARTS packets when there's enough gap material in the
    /// file to fill them. Regressing this to 1 would recreate the
    /// multi-second cold-pipe-stall on high-bandwidth peers.
    #[test]
    fn outstanding_requests_cold_start_uses_mid_tier_pipeline() {
        // Normal file: plenty of remaining parts, plenty of gap bytes.
        let packets = outstanding_requests_for_speed_ms(
            0,
            100,                         // remaining_parts > 4
            1024 * 1024 * 1024,          // plenty of gap to pull from
        );
        assert!(
            packets >= 2,
            "cold-start packet count should be at least 2, got {packets}",
        );
    }

    /// ...but small-file / endgame cases (remaining_parts <= 4) must stay
    /// conservative — the inner clamp at the bottom of the function
    /// caps to 3 packets when remaining_parts <= 2, and to 6 when
    /// <= 4, so the unknown-speed branch shouldn't leak the larger
    /// `blocks = 6` default in there and start over-requesting the tail
    /// of a small file.
    #[test]
    fn outstanding_requests_cold_start_respects_small_file_clamp() {
        let packets = outstanding_requests_for_speed_ms(0, 2, 1024);
        assert_eq!(
            packets, 1,
            "endgame with tiny gap should stay at a single outstanding request, got {packets}",
        );
    }
}

pub(crate) fn parse_browse_response(data: &[u8]) -> Vec<(String, u64, String)> {
    let mut entries = Vec::new();
    if data.len() < 4 { return entries; }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut pos = 4;
    for _ in 0..count.min(5000) {
        if pos + 16 + 8 + 2 > data.len() { break; }
        let hash = hex::encode(&data[pos..pos+16]);
        pos += 16;
        let size = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap_or([0;8]));
        pos += 8;
        let name_len = u16::from_le_bytes([data[pos], data[pos+1]]) as usize;
        pos += 2;
        if pos + name_len > data.len() { break; }
        let name = String::from_utf8_lossy(&data[pos..pos+name_len]).to_string();
        pos += name_len;
        entries.push((hash, size, name));
    }
    entries
}
