//! The publisher of a feed as a source of one of its files: the file over the
//! feed stream (see `network::feed_direct`), into the shared part file.
//!
//! The stream runs from the first chunk the download lacks to the end, each
//! 256 KiB chunk checked against the publisher's chunk list as it lands, over
//! QUIC pinned to the publisher's identity or a secure stream on its TCP port.
//! Like a web source it writes through the reserve, write and commit path a
//! peer does, so bytes peers or mirrors filled meanwhile are not written
//! twice, and the download's own checks judge the file: part hashes when a
//! peer hands a hashset over, and the whole-file eD2K, AICH and BLAKE3 the
//! feed's list names, at the end.

use super::web_worker::{ActiveRequest, Working};
use super::*;
use crate::network::ed2k::secure_stream::SecureStreamParts;
use crate::network::ed2k::transfer::SourceFailureKind;
use crate::network::ember::attach::{
    AttachStreamStatus, ATTACH_CHUNK_SIZE, ATTACH_CLOSE_ABANDONED, ATTACH_CLOSE_RECEIVED, FEED_STREAM_MSG_TYPE,
};
use crate::network::ember::attach_stream::{self, FetchError};
use crate::network::ember::attach_tcp::{self, Dialled};
use crate::network::feed_direct::{self, StreamSource};

/// How often the dispatcher looks for a stream registered since it started.
const DISPATCH_RECHECK: std::time::Duration = std::time::Duration::from_secs(2);
/// How long a QUIC dial may take before it counts as failed.
const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
/// Dials or streams in a row that may fail before the publisher is given up
/// on, and every network asked. One that moved bytes resets the count.
const MAX_FAILURES: u32 = 3;
/// How long between them.
const RETRY_PAUSE: std::time::Duration = std::time::Duration::from_secs(2);
/// Times in a row the publisher may say it is busy before it is given up on.
/// The download's hold ends meanwhile once nothing arrives, so the rest of
/// the network is asked while the publisher is asked again.
const MAX_BUSY: u32 = 8;
/// The pause after the first busy answer, doubled after each up to
/// [`BUSY_PAUSE_MAX`]: about ten minutes before it is given up on.
const BUSY_PAUSE: std::time::Duration = std::time::Duration::from_secs(15);
const BUSY_PAUSE_MAX: std::time::Duration = std::time::Duration::from_secs(120);
/// Chunks held already, ahead of the stream, past which it is asked again
/// from the next missing one rather than read on through.
const SKIP_CHUNKS: u64 = 4;

/// The pause after the `busy`th busy answer in a row.
fn busy_pause(busy: u32) -> std::time::Duration {
    BUSY_PAUSE.saturating_mul(1 << busy.saturating_sub(1).min(8)).min(BUSY_PAUSE_MAX)
}

/// Run the publisher's stream for the download once one is registered, until
/// the file is complete or the download stops. `first` is the download's
/// count of a stream registered before it started, taken so the download
/// never sees it idle in between.
pub(super) async fn dispatch(template: FeedWorker, mut first: Option<Working>, total_sources: Arc<AtomicU32>) {
    let mut running: Option<super::super::transfer::AbortOnDrop> = None;
    let mut counted = false;
    loop {
        if check_control(&template.control).await.is_err() || template.tracker.read().await.all_complete() {
            return;
        }
        if running.as_ref().is_none_or(|handle| handle.0.is_finished()) {
            running = None;
            match feed_direct::stream_for(&template.transfer_id) {
                Some(source) => {
                    if !counted {
                        total_sources.fetch_add(1, Ordering::Relaxed);
                        counted = true;
                    }
                    let working = first.take().unwrap_or_else(|| Working::new(&template.working));
                    let worker = template.clone();
                    running = Some(super::super::transfer::AbortOnDrop(tokio::spawn(async move {
                        worker.run(source, working).await;
                    })));
                }
                None => first = None,
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(DISPATCH_RECHECK) => {}
            _ = template.control.wait_cancel_or_pause() => {}
        }
    }
}

/// What the publisher's stream needs from the download it serves.
#[derive(Clone)]
pub(super) struct FeedWorker {
    /// Distinct from every peer and web worker's index.
    pub worker: usize,
    pub transfer_id: String,
    pub file_size: u64,
    pub tracker: Arc<RwLock<PartTracker>>,
    pub output: super::super::write_coordinator::PartFileWriter,
    pub bandwidth: Arc<BandwidthLimiter>,
    pub control: Arc<TransferControl>,
    pub progress_tx: mpsc::Sender<(usize, i64)>,
    pub event_tx: mpsc::Sender<DownloadEvent>,
    pub drop_tx: DropReleaseTx,
    pub active_count: Arc<AtomicU32>,
    pub disk_full: Arc<AtomicBool>,
    pub working: Arc<std::sync::atomic::AtomicUsize>,
    pub our_hash: [u8; 16],
    pub our_public_key: [u8; 32],
    pub our_secret_key: [u8; 32],
    pub ip_filter: Option<crate::network::kad::ip_filter::SharedIpFilter>,
    pub banned_ips: Option<super::super::upload::SharedBannedIps>,
}

/// How a run of the stream ended.
enum End {
    /// The file is whole.
    Complete,
    /// The publisher refused, sent what did not check, or could not be
    /// reached: every network is to be asked.
    Failed,
    /// The download stopped. The stream stays registered, for its next run.
    Stopped,
}

/// Why one stream ended short of the file's end.
enum PullError {
    Stopped,
    Fetch(FetchError),
}

impl FeedWorker {
    async fn run(self, source: StreamSource, working: Working) {
        let end = self.run_inner(&source).await;
        drop(working);
        match end {
            End::Complete => feed_direct::stream_finished(&self.transfer_id, true),
            End::Failed => {
                tracing::info!(
                    "Feed download {}: the publisher's stream failed; asking every network",
                    self.transfer_id
                );
                feed_direct::stream_finished(&self.transfer_id, false);
            }
            End::Stopped => {}
        }
    }

    async fn run_inner(&self, source: &StreamSource) -> End {
        let Ok((cert, key)) = crate::network::ember::quic::generate_self_signed_cert(&self.our_secret_key) else {
            return End::Failed;
        };
        self.report(source, "connecting", 0, 0, None).await;
        let mut failures = 0u32;
        let mut busy = 0u32;
        let mut root: Option<[u8; 32]> = None;
        let mut transferred = 0u64;
        loop {
            if check_control(&self.control).await.is_err() || disk_full_hit(&self.disk_full) {
                return End::Stopped;
            }
            let start = {
                let t = self.tracker.read().await;
                if t.all_complete() {
                    self.report(source, "completed", 0, transferred, None).await;
                    return End::Complete;
                }
                t.fillable_subranges(0, self.file_size).first().map(|&(start, _)| start)
            };
            // What is missing is mid-write by another source.
            let Some(start) = start else {
                self.pause(std::time::Duration::from_secs(1)).await;
                continue;
            };
            let start_chunk = u32::try_from(start / ATTACH_CHUNK_SIZE as u64).unwrap_or(u32::MAX);
            let mut written = 0u64;
            let pulled = match self.dial(source, &cert, &key).await {
                Dialled::Quic(conn) => match conn.open_bi().await {
                    Ok((mut send, mut recv)) => {
                        let pulled = self
                            .pull(source, &mut recv, &mut send, start_chunk, &mut root, &mut transferred, &mut written)
                            .await;
                        let _ = send.finish();
                        let reason = if matches!(pulled, Ok(true)) { ATTACH_CLOSE_RECEIVED } else { ATTACH_CLOSE_ABANDONED };
                        conn.close(0u32.into(), reason);
                        pulled
                    }
                    Err(e) => Err(PullError::Fetch(FetchError::Transient(e.into()))),
                },
                Dialled::Tcp(mut parts) => {
                    let pulled = self
                        .pull(source, &mut parts.reader, &mut parts.writer, start_chunk, &mut root, &mut transferred, &mut written)
                        .await;
                    if matches!(pulled, Ok(true)) {
                        // Best effort: the publisher only uses it to know its side is done.
                        let _ = parts.writer.write_all(&[attach_tcp::TCP_STREAM_RECEIVED]).await;
                        let _ = parts.writer.flush().await;
                    }
                    pulled
                }
                Dialled::Neither(()) => {
                    Err(PullError::Fetch(FetchError::Transient(anyhow::anyhow!("the publisher could not be reached"))))
                }
            };
            if written > 0 {
                failures = 0;
                busy = 0;
            }
            match pulled {
                // To the end, or stopped to skip what is held: the top of the
                // loop says whether anything is left.
                Ok(_) if written > 0 => continue,
                Ok(_) => failures += 1,
                Err(PullError::Stopped) => return End::Stopped,
                Err(PullError::Fetch(FetchError::Refused(AttachStreamStatus::Busy))) => {
                    busy += 1;
                    if busy >= MAX_BUSY {
                        debug!("Feed download {}: the publisher stayed busy; giving up on it", self.transfer_id);
                        self.report(source, "failed", 0, transferred, Some(SourceFailureKind::Transient)).await;
                        return End::Failed;
                    }
                    self.report(source, "queue_full", 0, transferred, None).await;
                    self.pause(busy_pause(busy)).await;
                    continue;
                }
                Err(PullError::Fetch(error @ (FetchError::Refused(_) | FetchError::Corrupt(_)))) => {
                    debug!("Feed download {}: the publisher's stream ended: {error}", self.transfer_id);
                    self.report(source, "failed", 0, transferred, Some(SourceFailureKind::Permanent)).await;
                    return End::Failed;
                }
                Err(PullError::Fetch(error)) => {
                    debug!("Feed download {}: the publisher's stream dropped: {error}", self.transfer_id);
                    failures += 1;
                }
            }
            if failures >= MAX_FAILURES {
                self.report(source, "failed", 0, transferred, Some(SourceFailureKind::Transient)).await;
                return End::Failed;
            }
            self.report(source, "connecting", 0, transferred, None).await;
            self.pause(RETRY_PAUSE).await;
        }
    }

    /// QUIC with the publisher's identity pinned, and once it has had a head
    /// start, its TCP port beside it; the first to connect is used.
    async fn dial(&self, source: &StreamSource, cert: &[u8], key: &[u8]) -> Dialled<quinn::Connection, SecureStreamParts, ()> {
        let tcp = source.tcp.filter(|addr| !self.address_refused(addr.ip()));
        let quic = source
            .quic
            .zip(source.endpoint.clone())
            .filter(|(addr, _)| !self.address_refused(addr.ip()));
        let Some((addr, endpoint)) = quic else {
            return match tcp {
                Some(tcp) => self.dial_tcp(tcp, source.publisher).await.map_or(Dialled::Neither(()), Dialled::Tcp),
                None => Dialled::Neither(()),
            };
        };
        let quic = async move {
            tokio::time::timeout(
                DIAL_TIMEOUT,
                crate::network::ember::quic::connect_pinned(&endpoint, addr, "ember", Some((cert, key, source.publisher))),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .ok_or(())
        };
        match tcp {
            Some(tcp) => attach_tcp::dial_quic_or_tcp(quic, || self.dial_tcp(tcp, source.publisher)).await,
            None => quic.await.map_or(Dialled::Neither(()), Dialled::Quic),
        }
    }

    async fn dial_tcp(&self, addr: std::net::SocketAddr, publisher: [u8; 16]) -> Option<SecureStreamParts> {
        attach_tcp::dial_secure(addr, self.our_hash, self.our_public_key, self.our_secret_key, publisher)
            .await
            .ok()
    }

    /// Ask for the file from `start_chunk` and write what is missing of each
    /// chunk as it lands. `Ok(true)` once the last chunk is read, `Ok(false)`
    /// when it stopped to skip chunks held already. Adds the bytes off the
    /// wire to `transferred` and those that filled a gap to `written`.
    #[allow(clippy::too_many_arguments)]
    async fn pull<R, W>(
        &self,
        source: &StreamSource,
        recv: &mut R,
        send: &mut W,
        start_chunk: u32,
        root: &mut Option<[u8; 32]>,
        transferred: &mut u64,
        written: &mut u64,
    ) -> Result<bool, PullError>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let info = tokio::select! {
            info = attach_stream::request_chunks(
                FEED_STREAM_MSG_TYPE,
                recv,
                send,
                &source.xfer_id,
                &source.capability,
                self.file_size,
                start_chunk,
                attach_stream::ATTACH_STATUS_TIMEOUT,
            ) => info.map_err(PullError::Fetch)?,
            _ = self.control.wait_cancel_or_pause() => return Err(PullError::Stopped),
        };
        // Every stream of a run must be of the same bytes: a list that changed
        // between two means a file that did, and what came before it is of
        // another.
        let list_root = crate::network::ember::transfer::root_from_chunk_hashes(&info.chunk_hashes);
        if root.is_some_and(|seen| seen != list_root) {
            return Err(PullError::Fetch(FetchError::Corrupt("the publisher's file changed between streams".into())));
        }
        *root = Some(list_root);
        feed_direct::stream_connected(&self.transfer_id);

        let _active = ActiveRequest::new(&self.active_count);
        let wire = self.tracker.read().await.transferred_counter();
        let mut buf = vec![0u8; ATTACH_CHUNK_SIZE];
        let mut window_start = std::time::Instant::now();
        let mut window_bytes = 0u64;
        let mut reported = false;
        for index in start_chunk as usize..info.chunk_count() {
            let offset = index as u64 * ATTACH_CHUNK_SIZE as u64;
            if self.held_ahead(offset).await {
                return Ok(false);
            }
            let len = info
                .chunk_len(index)
                .ok_or_else(|| PullError::Fetch(FetchError::Corrupt("chunk index past the end".into())))?;
            if !self.bandwidth.acquire_download(len as u64).await {
                return Err(PullError::Stopped);
            }
            tokio::select! {
                read = attach_stream::read_verified_chunk(recv, &info, index, &mut buf, |_| {}) => {
                    read.map_err(PullError::Fetch)?;
                }
                _ = self.control.wait_cancel_or_pause() => return Err(PullError::Stopped),
            }
            wire.fetch_add(len as u64, Ordering::Relaxed);
            *transferred = transferred.saturating_add(len as u64);
            window_bytes = window_bytes.saturating_add(len as u64);
            let outcome = write_gap_subranges_ms(
                &self.tracker,
                &self.output,
                offset,
                &buf[..len],
                self.worker,
                "feed ",
                Some(&self.drop_tx),
            )
            .await;
            if outcome.disk_full.is_some() {
                self.disk_full.store(true, Ordering::Relaxed);
                return Err(PullError::Stopped);
            }
            if !outcome.write_ok {
                return Err(PullError::Stopped);
            }
            *written = written.saturating_add(outcome.newly_written);
            if outcome.newly_written > 0 {
                let _ = self.progress_tx.try_send((self.worker, outcome.newly_written as i64));
            }
            let elapsed = window_start.elapsed();
            if !reported || elapsed >= std::time::Duration::from_secs(1) {
                let speed = (window_bytes as f64 / elapsed.as_secs_f64().max(0.001)) as u64;
                self.report(source, "transferring", speed, *transferred, None).await;
                reported = true;
                window_start = std::time::Instant::now();
                window_bytes = 0;
            }
        }
        Ok(true)
    }

    /// Whether the chunk at `offset` and the [`SKIP_CHUNKS`] after it are
    /// held already, by this stream before or by another source.
    async fn held_ahead(&self, offset: u64) -> bool {
        let end = offset
            .saturating_add(SKIP_CHUNKS * ATTACH_CHUNK_SIZE as u64)
            .min(self.file_size);
        end > offset && self.tracker.read().await.fillable_subranges(offset, end).is_empty()
    }

    /// Whether the IP filter or the ban list refuses `ip`, as they would any
    /// peer at that address.
    fn address_refused(&self, ip: std::net::IpAddr) -> bool {
        let std::net::IpAddr::V4(v4) = ip else {
            return false;
        };
        if let Some(filter) = &self.ip_filter {
            if filter.read().unwrap_or_else(|e| e.into_inner()).is_blocked(v4) {
                return true;
            }
        }
        self.banned_ips
            .as_ref()
            .is_some_and(|banned| banned.read().unwrap_or_else(|e| e.into_inner()).contains(&v4))
    }

    async fn report(&self, source: &StreamSource, status: &str, speed: u64, transferred: u64, kind: Option<SourceFailureKind>) {
        let addr = source.quic.or(source.tcp);
        let _ = self
            .event_tx
            .send(DownloadEvent::SourceDetail {
                transfer_id: self.transfer_id.clone(),
                ip: addr.map(|addr| addr.ip().to_string()).unwrap_or_default(),
                port: addr.map_or(0, |addr| addr.port()),
                status: status.to_string(),
                queue_rank: None,
                speed,
                transferred,
                client_software: "Ember".to_string(),
                peer_name: String::new(),
                failure_kind: kind,
                available_parts: None,
                total_parts: None,
                country_code: None,
            })
            .await;
    }

    /// Sleep `for_`, waking early if the download stops.
    async fn pause(&self, for_: std::time::Duration) {
        tokio::select! {
            _ = tokio::time::sleep(for_) => {}
            _ = self.control.wait_cancel_or_pause() => {}
        }
    }
}

#[cfg(test)]
// `test_registry_lock` is held across the awaits on purpose: it serialises
// tests that swap the process-global approved-root registry, and the part file
// is opened asynchronously. Current-thread runtimes, so no executor thread is
// stranded.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;

    const CHUNK: u64 = ATTACH_CHUNK_SIZE as u64;

    struct Rig {
        worker: FeedWorker,
        source: StreamSource,
        part: std::path::PathBuf,
        served: std::path::PathBuf,
        base: std::path::PathBuf,
        _events: mpsc::Receiver<DownloadEvent>,
        _progress: mpsc::Receiver<(usize, i64)>,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    /// A download of `data` with an empty part file, and the publisher's copy.
    async fn rig(tag: &str, data: &[u8]) -> Rig {
        let base = std::env::temp_dir().join(format!("ember-feed-worker-{tag}-{}-{}", std::process::id(), rand::random::<u64>()));
        let (root, data_dir) = (base.join("root"), base.join("data"));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data_dir).unwrap();
        let root_s = root.to_string_lossy().into_owned();
        crate::security::filesystem::initialize_approved_roots(&data_dir, std::slice::from_ref(&root_s)).unwrap();
        let part = root.join("file.part");
        std::fs::File::create(&part).unwrap().set_len(data.len() as u64).unwrap();
        let served = base.join("published");
        std::fs::write(&served, data).unwrap();
        let output = crate::network::ed2k::write_coordinator::PartFileWriter::open(part.clone(), vec![root_s], None)
            .await
            .unwrap();
        let tracker = Arc::new(RwLock::new(PartTracker::new(data.len() as u64, &part)));
        let drop_tx = spawn_drop_release_worker(tracker.clone(), Arc::new(RwLock::new(ChunkSelector::new(1))));
        let (progress_tx, progress) = mpsc::channel(4096);
        let (event_tx, events) = mpsc::channel(4096);
        let worker = FeedWorker {
            worker: FEED_WORKER_INDEX,
            transfer_id: format!("feed-worker-{tag}"),
            file_size: data.len() as u64,
            tracker,
            output,
            bandwidth: Arc::new(BandwidthLimiter::new(0, 0)),
            control: TransferControl::new(),
            progress_tx,
            event_tx,
            drop_tx,
            active_count: Arc::new(AtomicU32::new(0)),
            disk_full: Arc::new(AtomicBool::new(false)),
            working: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            our_hash: [0; 16],
            our_public_key: [0; 32],
            our_secret_key: [0; 32],
            ip_filter: None,
            banned_ips: None,
        };
        let source = StreamSource {
            publisher: [1; 16],
            xfer_id: [2; 16],
            capability: [3; 32],
            quic: None,
            tcp: None,
            endpoint: None,
        };
        Rig { worker, source, part, served, base, _events: events, _progress: progress }
    }

    fn data(chunks: u64) -> Vec<u8> {
        (0..chunks * CHUNK - 77).map(|i| (i % 251) as u8).collect()
    }

    /// Serve the rig's published copy once, and pull it from `start_chunk`.
    async fn pull_once(rig: &Rig, start_chunk: u32, root: &mut Option<[u8; 32]>) -> (Result<bool, PullError>, u64) {
        let (mut client_w, mut server_r) = tokio::io::duplex(1 << 20);
        let (mut server_w, mut client_r) = tokio::io::duplex(1 << 20);
        let (served, size, capability) = (rig.served.clone(), rig.worker.file_size, rig.source.capability);
        let server = tokio::spawn(async move {
            let mut prefix = [0u8; 7];
            server_r.read_exact(&mut prefix).await?;
            attach_stream::serve_feed_stream(
                &mut server_r,
                &mut server_w,
                &prefix,
                |_| Some((served, size, capability)),
                |_| Ok(()),
                |_, _, _| true,
                None,
            )
            .await
        });
        let (mut transferred, mut written) = (0, 0);
        let pulled = rig
            .worker
            .pull(&rig.source, &mut client_r, &mut client_w, start_chunk, root, &mut transferred, &mut written)
            .await;
        drop((client_r, client_w));
        let _ = server.await;
        (pulled, written)
    }

    async fn first_gap(rig: &Rig) -> Option<u64> {
        rig.worker
            .tracker
            .read()
            .await
            .fillable_subranges(0, rig.worker.file_size)
            .first()
            .map(|&(start, _)| start)
    }

    #[tokio::test]
    async fn the_publishers_stream_fills_the_part_file() {
        let _registry = crate::security::filesystem::test_registry_lock();
        let data = data(3);
        let rig = rig("fill", &data).await;
        let mut root = None;
        let (pulled, written) = pull_once(&rig, 0, &mut root).await;
        assert!(matches!(pulled, Ok(true)));
        assert_eq!(written, data.len() as u64);
        assert!(rig.worker.tracker.read().await.all_complete());
        assert_eq!(std::fs::read(&rig.part).unwrap(), data);
        assert_eq!(root, Some(crate::network::ember::transfer::HashTree::from_data(&data).root_hash));
    }

    /// Chunks another source filled are not read through: the stream stops
    /// short of them and is asked again from the next one missing.
    #[tokio::test]
    async fn chunks_held_already_are_skipped_rather_than_read_through() {
        let _registry = crate::security::filesystem::test_registry_lock();
        let data = data(SKIP_CHUNKS + 2);
        let rig = rig("skip", &data).await;
        let (held_from, held_to) = (CHUNK, (SKIP_CHUNKS + 1) * CHUNK);
        {
            use std::io::{Seek, Write};
            let mut part = std::fs::OpenOptions::new().write(true).open(&rig.part).unwrap();
            part.seek(std::io::SeekFrom::Start(held_from)).unwrap();
            part.write_all(&data[held_from as usize..held_to as usize]).unwrap();
        }
        rig.worker.tracker.write().await.fill_range(held_from, held_to);

        let mut root = None;
        let (pulled, written) = pull_once(&rig, 0, &mut root).await;
        assert!(matches!(pulled, Ok(false)), "stopped ahead of what is held");
        assert_eq!(written, CHUNK);
        let next = first_gap(&rig).await.expect("the last chunk is missing");
        assert_eq!(next, held_to);
        let (pulled, written) = pull_once(&rig, (next / CHUNK) as u32, &mut root).await;
        assert!(matches!(pulled, Ok(true)));
        assert_eq!(written, data.len() as u64 - held_to);
        assert!(rig.worker.tracker.read().await.all_complete());
        assert_eq!(std::fs::read(&rig.part).unwrap(), data);
    }

    /// A second stream of other bytes than the first, a file the publisher
    /// replaced meanwhile, is refused rather than spliced onto them.
    #[tokio::test]
    async fn a_file_changed_between_streams_is_refused() {
        let _registry = crate::security::filesystem::test_registry_lock();
        let data = data(2);
        let rig = rig("changed", &data).await;
        let mut root = Some([0xAB; 32]);
        let (pulled, written) = pull_once(&rig, 0, &mut root).await;
        assert!(matches!(pulled, Err(PullError::Fetch(FetchError::Corrupt(_)))));
        assert_eq!(written, 0);
        assert!(first_gap(&rig).await == Some(0), "nothing written");
    }

    #[tokio::test]
    async fn a_paused_download_stops_the_stream() {
        let _registry = crate::security::filesystem::test_registry_lock();
        let data = data(2);
        let rig = rig("paused", &data).await;
        rig.worker.control.pause();
        let (pulled, _) = pull_once(&rig, 0, &mut None).await;
        assert!(matches!(pulled, Err(PullError::Stopped)));
    }
}
