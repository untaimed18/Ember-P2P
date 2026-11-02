//! One web source of a download: fetch the parts no peer is working on with
//! HTTP `Range` requests, into the shared part file — and once every part left
//! has a source on it, a share of what one of them has left.
//!
//! A child of `multi_source` so it uses the same claim → reserve → write →
//! commit path, and the same MD4 sweep, as a peer worker — a mirror is one more
//! source of bytes, verified like any other. See `super::super::web_sources`
//! for the URL rules and the per-URL backoff this reports into.

use super::*;
use crate::network::ed2k::transfer::SourceFailureKind;
use crate::network::ed2k::web_sources;

/// Bytes gathered from the response body before each reserve/write/commit:
/// the eMule block size, so a write is the same unit a peer's would be.
const WRITE_CHUNK: usize = super::super::messages::EMBLOCKSIZE as usize;

/// A read that stalls this long ends the request; the next one resumes from
/// the gap map, so nothing written is lost.
const READ_IDLE: std::time::Duration = std::time::Duration::from_secs(30);

/// Least a mirror must send per [`THROUGHPUT_WINDOW`] to keep its range. The
/// idle timeout alone let one byte every 29 seconds hold a part, and with it
/// the end of the download, indefinitely.
const MIN_BYTES_PER_WINDOW: u64 = 64 * 1024;
const THROUGHPUT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// A pass that wrote less than this into a part still unfinished waits
/// [`THIN_PASS_PAUSE`] before asking again, so a mirror answering every range
/// with a byte or two is not re-asked in a tight loop.
const THIN_PASS_BYTES: u64 = WRITE_CHUNK as u64;
const THIN_PASS_PAUSE: std::time::Duration = std::time::Duration::from_secs(5);

/// Redirects followed per request, each re-validated like the first URL.
const MAX_REDIRECTS: usize = 5;

/// How far past where it is reading a mirror tells other workers it is
/// fetching. Its request runs to the end of its range, but published whole, a
/// second mirror joining the part found nothing left to take and streamed the
/// same bytes from the same offset: a part with N mirrors was downloaded N
/// times. Published this short, one joining starts beyond it, and the request
/// ends where it reaches bytes the other wrote ([`read_on`]).
const PUBLISHED_AHEAD: u64 = 4 * WRITE_CHUNK as u64;

/// How long to wait when nothing is left to fetch but bytes another source is
/// writing right now, and how often a resting source looks again.
const IDLE_RECHECK: std::time::Duration = std::time::Duration::from_secs(5);

/// How often the dispatcher looks for web sources added since it started —
/// a link with mirrors pasted again for a file already downloading.
const DISPATCH_RECHECK: std::time::Duration = std::time::Duration::from_secs(15);

/// Run a worker for each web source of the download as it becomes ready,
/// until the file is complete or the download stops. It does not end when no
/// source is ready: one may be added, finish resting, or be switched back on
/// while the download runs. The download aborts it once the peers are done
/// and no worker is fetching (`WebWorker::working`).
///
/// One task owns them all so the download waits on one handle, and holds each
/// worker in an [`super::super::transfer::AbortOnDrop`] so that aborting it —
/// which every early exit of the download does — stops every worker with it.
/// A dropped `JoinHandle` alone would leave them writing to a part file the
/// next run of the download is about to open.
pub(super) async fn dispatch(template: WebWorker, total_sources: Arc<AtomicU32>) {
    let mut running: HashMap<String, super::super::transfer::AbortOnDrop> = HashMap::new();
    let mut counted: HashSet<String> = HashSet::new();
    let mut next_worker = 0usize;
    loop {
        if check_control(&template.control).await.is_err()
            || template.tracker.read().await.all_complete()
        {
            return;
        }
        running.retain(|_, handle| !handle.0.is_finished());
        for url in web_sources::ready(&template.file_hash) {
            if running.contains_key(&url) {
                continue;
            }
            if counted.insert(url.clone()) {
                total_sources.fetch_add(1, Ordering::Relaxed);
            }
            let mut worker = template.clone();
            worker.url = url.clone();
            worker.worker = template.worker + next_worker;
            next_worker += 1;
            // Counted before the spawn, so the download never sees a gap
            // between a source being ready and its worker starting.
            let working = Working::new(&template.working);
            let handle = tokio::spawn(async move {
                let _ = worker.run(working).await;
            });
            running.insert(url, super::super::transfer::AbortOnDrop(handle));
        }
        tokio::select! {
            _ = tokio::time::sleep(DISPATCH_RECHECK) => {}
            _ = template.control.wait_cancel_or_pause() => {}
        }
    }
}

/// What a web source worker needs from the download it serves.
#[derive(Clone)]
pub(super) struct WebWorker {
    pub url: String,
    /// Distinct from every peer worker's index, for claims and log lines.
    pub worker: usize,
    pub transfer_id: String,
    pub file_hash: [u8; 16],
    pub file_size: u64,
    pub tracker: Arc<RwLock<PartTracker>>,
    pub output: super::super::write_coordinator::PartFileWriter,
    pub part_hashes: Arc<RwLock<Vec<[u8; 16]>>>,
    pub bandwidth: Arc<BandwidthLimiter>,
    pub control: Arc<TransferControl>,
    pub progress_tx: mpsc::Sender<(usize, i64)>,
    pub event_tx: mpsc::Sender<DownloadEvent>,
    pub drop_tx: DropReleaseTx,
    pub active_count: Arc<AtomicU32>,
    pub disk_full: Arc<AtomicBool>,
    /// Workers fetching or ready to, shared by all of them: one resting out
    /// its backoff is not counted, so the download does not wait on it.
    pub working: Arc<std::sync::atomic::AtomicUsize>,
    /// The filter and bans every peer of the download is held to. A mirror
    /// sees this computer's address as a peer does, so one in a range the
    /// user blocked is not contacted either.
    pub ip_filter: Option<crate::network::kad::ip_filter::SharedIpFilter>,
    pub banned_ips: Option<super::super::upload::SharedBannedIps>,
}

/// Counts its worker in `WebWorker::working` while held. A feed's publisher
/// stream (`super::feed_worker`) counts in the same, so the download waits on
/// it as on a mirror.
pub(super) struct Working {
    count: Arc<std::sync::atomic::AtomicUsize>,
    held: bool,
}

impl Working {
    pub(super) fn new(count: &Arc<std::sync::atomic::AtomicUsize>) -> Self {
        let mut working = Self { count: count.clone(), held: false };
        working.hold();
        working
    }

    pub(super) fn hold(&mut self) {
        if !self.held {
            self.count.fetch_add(1, Ordering::Relaxed);
            self.held = true;
        }
    }

    pub(super) fn release(&mut self) {
        if self.held {
            self.count.fetch_sub(1, Ordering::Relaxed);
            self.held = false;
        }
    }
}

impl Drop for Working {
    fn drop(&mut self) {
        self.release();
    }
}

/// Counts a request in the download's active sources while its body streams.
/// A guard rather than a pair of calls: the worker is aborted mid-await on
/// every early exit of the download, which would skip the decrement.
pub(super) struct ActiveRequest(Arc<AtomicU32>);

impl ActiveRequest {
    pub(super) fn new(count: &Arc<AtomicU32>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self(count.clone())
    }
}

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// How a request that did not fail ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fetched {
    /// Its range is read, or the body ran out first.
    Done,
    /// Another source wrote the bytes it reached; what that source fetches
    /// lies ahead, so the part is picked from again.
    Overtaken,
    /// Web sources were switched off, or this one retired or replaced.
    Withdrawn,
}

/// How a request ended, which decides what the source is told.
enum FetchError {
    /// The server will never serve this file in parts: missing, refused, or
    /// ignoring `Range`. Retires the source.
    Permanent(String),
    /// Worth another try later: a timeout, a 5xx, a dropped connection.
    Transient(String),
    /// The download is stopping or the disk is full; not the server's fault.
    Stopped(anyhow::Error),
}

impl WebWorker {
    /// Whether the IP filter or the ban list refuses `ip`, as they would a
    /// peer at that address. Both are IPv4 only.
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

    /// Shown in the source list: host as the address, the URL as the name.
    fn host_and_port(&self) -> (String, u16) {
        reqwest::Url::parse(&self.url)
            .ok()
            .map(|u| {
                (
                    u.host_str().unwrap_or("web").to_string(),
                    u.port_or_known_default().unwrap_or(0),
                )
            })
            .unwrap_or_else(|| ("web".to_string(), 0))
    }

    async fn report(&self, status: &str, speed: u64, transferred: u64, kind: Option<SourceFailureKind>) {
        let (host, port) = self.host_and_port();
        // The protocol as the client name — the same in every language — with
        // the URL beside it as the name, which is what tells mirrors apart.
        let label = web_sources::source_label(&self.url);
        let _ = self
            .event_tx
            .send(DownloadEvent::SourceDetail {
                transfer_id: self.transfer_id.clone(),
                ip: host,
                port,
                status: status.to_string(),
                queue_rank: None,
                speed,
                transferred,
                client_software: label.to_string(),
                peer_name: crate::security::sanitize_remote_text(&self.url, 200),
                failure_kind: kind,
                available_parts: None,
                total_parts: None,
                country_code: None,
            })
            .await;
    }

    /// Run until the file is complete, the download stops, or this source has
    /// nothing more to give. Returns the shape every source task returns.
    async fn run(self, working: Working) -> (usize, Vec<usize>, anyhow::Result<()>) {
        let worker = self.worker;
        let result = self.run_inner(working).await;
        (worker, Vec::new(), result)
    }

    async fn run_inner(self, mut working: Working) -> anyhow::Result<()> {
        self.adopt_single_part_hash().await;
        self.report("connecting", 0, 0, None).await;
        let mut guard = InProgressGuard::with_release_tx(
            self.tracker.clone(),
            self.worker,
            self.drop_tx.clone(),
        );
        let mut transferred: u64 = 0;
        // The address the last redirect landed on, reused until it fails so a
        // mirror behind a redirector is not re-resolved for every range.
        let mut effective_url = self.url.clone();
        loop {
            check_control(&self.control).await?;
            if disk_full_hit(&self.disk_full) || self.tracker.read().await.all_complete() {
                break;
            }
            if !web_sources::enabled() {
                break;
            }
            // Retired elsewhere: by a corrupt part charged to it, judged
            // wherever that happened (see `web_sources::note_corrupt_range`),
            // by the download giving up on every mirror, or replaced by a new
            // mirror.
            if web_sources::is_retired(&self.file_hash, &self.url) {
                debug!("Web source {} retired for {}", self.url, self.transfer_id);
                self.report("failed", 0, transferred, Some(SourceFailureKind::Permanent)).await;
                return Ok(());
            }
            let picked = {
                let mut t = self.tracker.write().await;
                let picked = pick(&t, self.worker);
                if let Some((p, ranges)) = &picked {
                    guard.claim_locked(*p, &mut t);
                    // With the claim, so a mirror picking next sees where this
                    // one starts.
                    if let Some(&(start, end)) = ranges.first() {
                        t.publish_in_flight_requests(self.worker, vec![ahead(start, end)]);
                    }
                }
                picked
            };
            let Some((part, gaps)) = picked else {
                // Nothing left that is not mid-write by someone else.
                self.pause(IDLE_RECHECK).await;
                continue;
            };
            if gaps.is_empty() {
                // Its missing bytes are all mid-write by someone else.
                {
                    let mut t = self.tracker.write().await;
                    guard.release_locked(part, &mut t);
                }
                self.pause(std::time::Duration::from_millis(250)).await;
                continue;
            }

            let mut written: u64 = 0;
            let mut outcome: Result<Fetched, FetchError> = Ok(Fetched::Done);
            for (gs, ge) in gaps {
                outcome = self
                    .fetch_range(&mut effective_url, gs, ge, &mut transferred, &mut written)
                    .await;
                if !matches!(outcome, Ok(Fetched::Done)) {
                    break;
                }
            }
            guard.publish_in_flight(&[], None).await;
            // Check what this source just filled now, while the claim still
            // keeps the sweep off it, so a bad mirror is found out after one
            // part. On a part it shared with another source, the verdict is
            // about both, and a mirror is only charged for one it wrote alone
            // or AICH narrows to it (`web_sources::note_corrupt_range`).
            //
            // Not while another source still holds the part, as one this mirror
            // joined does: that source hashes it when its own fetch ends, and on
            // a mismatch it may be waiting on an AICH answer that narrows the
            // repair to one block. Hashing here as well reopened the whole part
            // under it, so the answer was thrown away and the part fetched again
            // in full with nobody blamed. A part nobody else holds is still
            // checked here; one left complete and unclaimed goes to the sweep.
            let (to_check, part_done) = {
                let t = self.tracker.read().await;
                let (ps, pe) = t.part_range(part);
                let done = t.is_part_complete(part);
                let shared = t.claims_on(part) > 1;
                (
                    (outcome.is_ok() && done && !shared && !t.is_part_verified(part))
                        .then(|| ((ps, pe), t.part_content_generation(part))),
                    done,
                )
            };
            let hashes = self.part_hashes.read().await.clone();
            let checked = match to_check {
                Some((range, generation)) if hashes.len() > part => Some((
                    range,
                    hash_claimed_part(
                        &self.tracker,
                        &hashes,
                        &self.output,
                        &mut guard,
                        part,
                        range,
                        generation,
                        &self.file_hash,
                        &self.event_tx,
                    )
                    .await,
                )),
                _ => {
                    let mut t = self.tracker.write().await;
                    guard.release_locked(part, &mut t);
                    None
                }
            };

            match outcome {
                Ok(fetched) => {
                    web_sources::note_success(&self.file_hash, &self.url);
                    match fetched {
                        Fetched::Done if written < THIN_PASS_BYTES && !part_done => {
                            self.pause(THIN_PASS_PAUSE).await;
                        }
                        // Another source wrote everything it read: a breath
                        // before picking again, so a lost race is not re-run
                        // in a tight loop.
                        Fetched::Overtaken if written == 0 => {
                            self.pause(std::time::Duration::from_millis(250)).await;
                        }
                        _ => {}
                    }
                }
                Err(FetchError::Stopped(e)) => return Err(e),
                Err(FetchError::Permanent(why)) => {
                    warn!("Web source {} retired for {}: {why}", self.url, self.transfer_id);
                    web_sources::note_failure(&self.file_hash, &self.url, true);
                    self.report("failed", 0, transferred, Some(SourceFailureKind::Permanent)).await;
                    return Ok(());
                }
                Err(FetchError::Transient(why)) => {
                    debug!("Web source {} failed for {}: {why}", self.url, self.transfer_id);
                    // A connection that dropped after delivering data is one
                    // failure, not one more in a run: a mirror that keeps
                    // making progress is rested, never retired for it.
                    if written > 0 {
                        web_sources::note_success(&self.file_hash, &self.url);
                    }
                    web_sources::note_failure(&self.file_hash, &self.url, false);
                    self.report("failed", 0, transferred, Some(SourceFailureKind::Transient)).await;
                    // Rest as long as the backoff says, then carry on; a source
                    // that keeps failing is retired by it and this ends.
                    effective_url = self.url.clone();
                    working.release();
                    if !self.wait_until_ready().await {
                        return Ok(());
                    }
                    working.hold();
                    self.report("connecting", 0, transferred, None).await;
                    continue;
                }
            }

            if let Some((_, ClaimedPartCheck::Corrupt)) = checked {
                warn!(
                    "Part {part} filled by web source {} failed verification",
                    self.url
                );
            }
        }
        self.report("completed", 0, transferred, None).await;
        Ok(())
    }

    /// Sleep `for_`, waking early if the download stops.
    async fn pause(&self, for_: std::time::Duration) {
        tokio::select! {
            _ = tokio::time::sleep(for_) => {}
            _ = self.control.wait_cancel_or_pause() => {}
        }
    }

    /// Wait out this source's backoff. `false` when it was retired instead,
    /// the feature was switched off, or the download stopped or finished.
    async fn wait_until_ready(&self) -> bool {
        loop {
            if self.control.is_cancelled()
                || self.control.is_paused()
                || !web_sources::enabled()
                || self.tracker.read().await.all_complete()
            {
                return false;
            }
            if web_sources::ready(&self.file_hash).contains(&self.url) {
                return true;
            }
            if web_sources::is_retired(&self.file_hash, &self.url) {
                return false;
            }
            self.pause(IDLE_RECHECK).await;
        }
    }

    /// A file of one part has its file hash as that part's MD4, so it can be
    /// verified part by part with no peer to hand over a hashset — which a
    /// download with only web sources would otherwise never get.
    async fn adopt_single_part_hash(&self) {
        let single = self.tracker.read().await.part_count == 1;
        if !single || !self.part_hashes.read().await.is_empty() {
            return;
        }
        let hashes = vec![self.file_hash];
        if super::super::transfer::verify_hashset(&self.file_hash, &hashes, self.file_size) {
            install_verified_part_hashes(&self.part_hashes, &self.tracker, hashes).await;
        }
    }

    /// Fetch `[start, end)` and write what is still missing of it. Adds the
    /// bytes off the wire to `transferred` and those that filled a gap to
    /// `written`.
    async fn fetch_range(
        &self,
        effective_url: &mut String,
        start: u64,
        end: u64,
        transferred: &mut u64,
        written: &mut u64,
    ) -> Result<Fetched, FetchError> {
        self.tracker
            .write()
            .await
            .publish_in_flight_requests(self.worker, vec![ahead(start, end)]);
        let response = match self.send_range(effective_url, start, end).await {
            Ok(r) => r,
            Err(e @ (FetchError::Permanent(_) | FetchError::Transient(_)))
                if effective_url.as_str() != self.url =>
            {
                // The redirect target may be what failed; start again from the
                // address the link named.
                debug!(
                    "Web source redirect target failed ({}), retrying {}",
                    fetch_error_text(&e),
                    self.url
                );
                *effective_url = self.url.clone();
                self.send_range(effective_url, start, end).await?
            }
            Err(e) => return Err(e),
        };

        let status = response.status().as_u16();
        // We ask for `identity`; a range of an encoded body is a range of the
        // encoding, and writing it would only cost a failed part hash. Error
        // pages are often compressed, so only a body we would write counts.
        if matches!(status, 200 | 206)
            && is_encoded(response.headers().get(reqwest::header::CONTENT_ENCODING))
        {
            return Err(FetchError::Permanent(
                "the server sends the file encoded".to_string(),
            ));
        }

        // Where the body starts, which a server ignoring `Range` puts at 0.
        let body_start = match status {
            206 => {
                let header = response
                    .headers()
                    .get(reqwest::header::CONTENT_RANGE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default();
                match parse_content_range(header) {
                    Some((first, _last, total)) => {
                        if total.is_some_and(|t| t != self.file_size) {
                            return Err(FetchError::Permanent(format!(
                                "the server's file is {} bytes, not {}",
                                total.unwrap_or(0),
                                self.file_size
                            )));
                        }
                        if first != start {
                            return Err(FetchError::Permanent(format!(
                                "asked for bytes from {start}, got them from {first}"
                            )));
                        }
                        first
                    }
                    None => {
                        return Err(FetchError::Permanent(
                            "partial answer without a usable Content-Range".to_string(),
                        ))
                    }
                }
            }
            200 => {
                // The whole file. Usable only for a range at its start: reading
                // the rest away to reach a later one would cost the file.
                let length_ok = response
                    .content_length()
                    .is_none_or(|len| len == self.file_size);
                if start != 0 || !length_ok {
                    return Err(FetchError::Permanent(
                        "the server does not serve parts of the file".to_string(),
                    ));
                }
                0
            }
            404 | 410 => return Err(FetchError::Permanent("the file is not on the server".into())),
            401 | 403 => return Err(FetchError::Permanent("the server refused access".into())),
            416 => return Err(FetchError::Permanent("the server's file is shorter".into())),
            status => {
                return Err(FetchError::Transient(format!("server answered {status}")));
            }
        };

        let _active = ActiveRequest::new(&self.active_count);
        self.stream_body(response, body_start, end, transferred, written)
            .await
    }

    /// GET `url` for bytes `[start, end)`, following redirects by hand so each
    /// hop is validated and DNS-pinned like the first.
    async fn send_range(
        &self,
        url: &mut String,
        start: u64,
        end: u64,
    ) -> Result<reqwest::Response, FetchError> {
        let user_agent = format!("Ember/{}", env!("CARGO_PKG_VERSION"));
        for _ in 0..=MAX_REDIRECTS {
            let (validated, host, addrs) = crate::security::validate_fetch_url_with(url, true)
                .await
                .map_err(|e| {
                    // A lookup that failed or timed out may work next time; an
                    // address the rules refuse never will.
                    if e.starts_with("DNS lookup") || e.contains("could not be resolved") {
                        FetchError::Transient(e)
                    } else {
                        FetchError::Permanent(e)
                    }
                })?;
            let addrs: Vec<std::net::SocketAddr> =
                addrs.into_iter().filter(|addr| !self.address_refused(addr.ip())).collect();
            if addrs.is_empty() {
                return Err(FetchError::Permanent(format!(
                    "{host} is blocked by the IP filter or banned"
                )));
            }
            let client = crate::security::build_pinned_web_source_client(
                &host,
                &addrs,
                &user_agent,
                READ_IDLE,
            )
            .map_err(FetchError::Transient)?;
            let request = client
                .get(&validated)
                .header(reqwest::header::RANGE, format!("bytes={start}-{}", end - 1))
                // A range of an encoded body is a range of the encoding, not of
                // the file.
                .header(reqwest::header::ACCEPT_ENCODING, "identity");
            let response = tokio::select! {
                r = request.send() => r.map_err(|e| FetchError::Transient(format!("request failed: {e}")))?,
                _ = self.control.wait_cancel_or_pause() => {
                    return Err(FetchError::Stopped(anyhow::anyhow!("cancelled by user")));
                }
            };
            // Only the codes that name a new location for the same resource:
            // 300 is a choice to make and 304 a cache answer to a conditional
            // request we never send.
            if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| FetchError::Transient("redirect without a Location".into()))?;
                let next = reqwest::Url::parse(&validated)
                    .and_then(|base| base.join(location))
                    .map_err(|e| FetchError::Permanent(format!("bad redirect: {e}")))?;
                *url = next.to_string();
                continue;
            }
            return Ok(response);
        }
        Err(FetchError::Permanent(format!("more than {MAX_REDIRECTS} redirects")))
    }

    /// Read the body from `body_start`, writing each chunk of `[.., end)` that
    /// is still missing, until `end` or the body runs out.
    async fn stream_body(
        &self,
        mut response: reqwest::Response,
        body_start: u64,
        end: u64,
        transferred: &mut u64,
        written: &mut u64,
    ) -> Result<Fetched, FetchError> {
        let wire = self.tracker.read().await.transferred_counter();
        let mut pos = body_start;
        let mut buf: Vec<u8> = Vec::with_capacity(WRITE_CHUNK);
        let mut window_start = std::time::Instant::now();
        let mut window_bytes: u64 = 0;
        let mut floor_start = std::time::Instant::now();
        let mut floor_bytes: u64 = 0;
        let mut reported_transferring = false;
        let mut got_any = false;
        loop {
            if !web_sources::enabled() || web_sources::is_retired(&self.file_hash, &self.url) {
                // Switched off, retired or replaced mid-request. What was
                // written stays; the worker ends at the top of its loop rather
                // than after a whole part.
                return Ok(Fetched::Withdrawn);
            }
            let chunk = tokio::select! {
                c = response.chunk() => c.map_err(|e| FetchError::Transient(format!("read failed: {e}")))?,
                _ = self.control.wait_cancel_or_pause() => {
                    return Err(FetchError::Stopped(anyhow::anyhow!("cancelled by user")));
                }
            };
            let done = chunk.is_none();
            if let Some(bytes) = chunk {
                floor_bytes = floor_bytes.saturating_add(bytes.len() as u64);
                let room = end.saturating_sub(pos + buf.len() as u64) as usize;
                buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
            }
            if floor_start.elapsed() >= THROUGHPUT_WINDOW {
                if floor_bytes < MIN_BYTES_PER_WINDOW {
                    return Err(FetchError::Transient(format!(
                        "too slow: {floor_bytes} bytes in {} s",
                        THROUGHPUT_WINDOW.as_secs()
                    )));
                }
                floor_start = std::time::Instant::now();
                floor_bytes = 0;
            }
            let at_end = pos + buf.len() as u64 >= end;
            if buf.len() >= WRITE_CHUNK || ((done || at_end) && !buf.is_empty()) {
                let len = buf.len() as u64;
                if !self.bandwidth.acquire_download(len).await {
                    return Err(FetchError::Stopped(anyhow::anyhow!("bandwidth limiter stopped")));
                }
                wire.fetch_add(len, Ordering::Relaxed);
                *transferred = transferred.saturating_add(len);
                window_bytes = window_bytes.saturating_add(len);
                let outcome = write_gap_subranges_ms(
                    &self.tracker,
                    &self.output,
                    pos,
                    &buf,
                    self.worker,
                    "web ",
                    Some(&self.drop_tx),
                )
                .await;
                if let Some(e) = outcome.disk_full {
                    self.disk_full.store(true, Ordering::Relaxed);
                    return Err(FetchError::Stopped(anyhow::anyhow!(
                        "stage:insufficient_disk disk write failed: {e}"
                    )));
                }
                if !outcome.write_ok {
                    return Err(FetchError::Stopped(anyhow::anyhow!("disk write failed")));
                }
                *written = written.saturating_add(outcome.newly_written);
                web_sources::note_written(&self.file_hash, &self.url, &outcome.written_subranges);
                if outcome.newly_written > 0 {
                    let _ = self
                        .progress_tx
                        .try_send((self.worker, outcome.newly_written as i64));
                }
                got_any = true;
                pos += len;
                buf.clear();
                if pos < end {
                    let keep = read_on(&mut *self.tracker.write().await, self.worker, pos, end);
                    if !keep {
                        return Ok(Fetched::Overtaken);
                    }
                }
                let elapsed = window_start.elapsed();
                if !reported_transferring || elapsed >= std::time::Duration::from_secs(1) {
                    let speed = (window_bytes as f64 / elapsed.as_secs_f64().max(0.001)) as u64;
                    self.report("transferring", speed, *transferred, None).await;
                    reported_transferring = true;
                    window_start = std::time::Instant::now();
                    window_bytes = 0;
                }
            }
            if pos >= end {
                return Ok(Fetched::Done);
            }
            if done {
                // Short body: what came is written, and the gap map says what
                // is left. Nothing at all is a failure.
                return if got_any {
                    Ok(Fetched::Done)
                } else {
                    Err(FetchError::Transient("the server sent no data".to_string()))
                };
            }
        }
    }
}

impl From<FetchError> for anyhow::Error {
    fn from(e: FetchError) -> Self {
        match e {
            FetchError::Permanent(s) | FetchError::Transient(s) => anyhow::anyhow!(s),
            FetchError::Stopped(e) => e,
        }
    }
}

fn fetch_error_text(e: &FetchError) -> &str {
    match e {
        FetchError::Permanent(s) | FetchError::Transient(s) => s,
        FetchError::Stopped(_) => "stopped",
    }
}

fn is_encoded(content_encoding: Option<&reqwest::header::HeaderValue>) -> bool {
    content_encoding.is_some_and(|v| {
        let v = v.as_bytes().trim_ascii();
        !v.is_empty() && !v.eq_ignore_ascii_case(b"identity") && !v.eq_ignore_ascii_case(b"none")
    })
}

/// `ranges` with every part covered by one of `cut` taken out. `cut` may
/// overlap itself (several workers' requests); `ranges` is sorted and disjoint.
fn without_ranges(ranges: &[(u64, u64)], cut: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for &(start, end) in ranges {
        let mut pieces = vec![(start, end)];
        for &(cs, ce) in cut {
            if cs >= ce {
                continue;
            }
            pieces = pieces
                .into_iter()
                .flat_map(|(s, e)| {
                    if ce <= s || cs >= e {
                        vec![(s, e)]
                    } else {
                        [(s, cs.max(s)), (ce.min(e), e)].into_iter().filter(|&(a, b)| a < b).collect()
                    }
                })
                .collect();
        }
        out.extend(pieces);
    }
    out
}

/// What `worker`, a mirror, fetches next: a part nobody holds, its gaps in
/// order; or, with every unfinished part held, one range of one of them
/// ([`join_range`]). Joining rather than sitting idle behind a slow peer
/// holding the last part — or the only one, on a file of a single part — as a
/// peer's own fallback does.
fn pick(t: &PartTracker, worker: usize) -> Option<(usize, Vec<(u64, u64)>)> {
    let claimed = t.in_progress_flags();
    let free = (0..t.part_count)
        .find(|&p| !t.is_part_complete(p) && !claimed.get(p).copied().unwrap_or(false));
    if let Some(p) = free {
        let (ps, pe) = t.part_range(p);
        return Some((p, t.fillable_subranges(ps, pe)));
    }
    let others = t.requested_by_others(worker);
    (0..t.part_count)
        .filter(|&p| !t.is_part_complete(p))
        .filter_map(|p| {
            let (ps, pe) = t.part_range(p);
            join_range(ps, &t.fillable_subranges(ps, pe), &others).map(|(range, unrequested)| (p, range, unrequested))
        })
        .max_by_key(|&(p, (start, end), unrequested)| (unrequested, end - start, std::cmp::Reverse(p)))
        .map(|(p, range, _)| (p, vec![range]))
}

/// The range a mirror joining a part takes, given the part's `gaps` and what
/// other workers have in flight, with how many bytes of the part nobody has
/// asked for, which decides the part to join. As eMule's endgame does, it
/// splits what is left rather than stream it beside another source:
///
/// - The largest span nobody has asked for, from its middle when a worker's
///   requests run up to it — that worker is heading in, and the two meet
///   halfway — or else from its start.
/// - With nothing unasked for, the back half of the largest range another
///   worker has in flight, down to racing one block whole.
fn join_range(part_start: u64, gaps: &[(u64, u64)], others: &[(u64, u64)]) -> Option<((u64, u64), u64)> {
    let largest =
        |ranges: &[(u64, u64)]| ranges.iter().copied().max_by_key(|&(s, e)| (e - s, std::cmp::Reverse(s)));
    let unrequested = without_ranges(gaps, others);
    if let Some((start, end)) = largest(&unrequested) {
        let heading_in = others.iter().any(|&(os, oe)| os < start && oe >= start);
        let from = if heading_in { split_point(part_start, start, end) } else { start };
        return Some(((from, end), unrequested.iter().map(|&(s, e)| e - s).sum()));
    }
    let in_flight: Vec<(u64, u64)> = others
        .iter()
        .flat_map(|&(os, oe)| {
            gaps.iter()
                .map(move |&(gs, ge)| (gs.max(os), ge.min(oe)))
                .filter(|&(s, e)| s < e)
        })
        .collect();
    let (start, end) = largest(&in_flight)?;
    Some(((split_point(part_start, start, end), end), 0))
}

/// Where a second source starts in `[start, end)` so that it and one coming
/// from `start` meet halfway: the middle, up to a block of the part as peers
/// ask for them, since the one coming is already reading while the second
/// still has to ask. `start`, for the whole span, when no block boundary lies
/// between the middle and `end`.
fn split_point(part_start: u64, start: u64, end: u64) -> u64 {
    let block = WRITE_CHUNK as u64;
    let middle = start + (end - start) / 2;
    let boundary = part_start + (middle - part_start).div_ceil(block) * block;
    if boundary < end {
        boundary.max(start)
    } else {
        start
    }
}

/// What a mirror reading from `pos` toward `end` publishes as in flight.
fn ahead(pos: u64, end: u64) -> (u64, u64) {
    (pos, end.min(pos.saturating_add(PUBLISHED_AHEAD)))
}

/// After writing up to `pos` of a request running to `end`, whether to read
/// on. Not once another source has written the byte at `pos`: it got there
/// first, so what it is fetching lies ahead and reading on would download it
/// a second time — two mirrors that split a part stop where they meet. Reading
/// on, `worker` publishes the stretch about to come in.
fn read_on(t: &mut PartTracker, worker: usize, pos: u64, end: u64) -> bool {
    if t.fillable_subranges(pos, pos + 1).is_empty() {
        return false;
    }
    t.publish_in_flight_requests(worker, vec![ahead(pos, end)]);
    true
}

/// `bytes first-last/total` → `(first, last, total)`; `total` is `None` for
/// `*`. Anything else, or a range that runs backwards, is `None`.
fn parse_content_range(header: &str) -> Option<(u64, u64, Option<u64>)> {
    let rest = header.trim().strip_prefix("bytes")?.trim_start();
    let (range, total) = rest.split_once('/')?;
    let (first, last) = range.trim().split_once('-')?;
    let first: u64 = first.trim().parse().ok()?;
    let last: u64 = last.trim().parse().ok()?;
    if last < first {
        return None;
    }
    let total = match total.trim() {
        "*" => None,
        t => Some(t.parse().ok()?),
    };
    Some((first, last, total))
}

#[cfg(test)]
mod tests {
    use super::{
        ahead, is_encoded, join_range, parse_content_range, pick, read_on, split_point, without_ranges, PartTracker,
        PUBLISHED_AHEAD, WRITE_CHUNK,
    };
    use reqwest::header::HeaderValue;

    const BLOCK: u64 = WRITE_CHUNK as u64;

    #[test]
    fn requested_ranges_are_cut_out_of_the_gaps() {
        assert_eq!(without_ranges(&[(0, 100)], &[]), vec![(0, 100)]);
        assert_eq!(without_ranges(&[(0, 100)], &[(20, 30)]), vec![(0, 20), (30, 100)]);
        assert_eq!(without_ranges(&[(0, 100)], &[(0, 100)]), vec![]);
        assert_eq!(
            without_ranges(&[(0, 50), (60, 100)], &[(40, 70), (45, 65), (90, 200)]),
            vec![(0, 40), (70, 90)],
            "overlapping requests, and one past the end"
        );
        assert_eq!(without_ranges(&[(10, 20)], &[(30, 40), (5, 5)]), vec![(10, 20)], "disjoint and empty cuts");
    }

    /// One part, one slow peer with a block in flight: a mirror joining takes
    /// what nobody asked for rather than wait behind it, from halfway, since
    /// the peer is heading into it from the front.
    #[test]
    fn a_mirror_joining_a_part_takes_what_nobody_asked_for() {
        assert_eq!(join_range(0, &[(0, 10 * BLOCK)], &[(0, BLOCK)]), Some(((6 * BLOCK, 10 * BLOCK), 9 * BLOCK)));

        // Nobody heading into the span: it is taken from its start.
        assert_eq!(
            join_range(0, &[(0, 10 * BLOCK)], &[(8 * BLOCK, 9 * BLOCK)]),
            Some(((0, 8 * BLOCK), 9 * BLOCK))
        );

        assert_eq!(
            join_range(0, &[(0, BLOCK)], &[(0, BLOCK)]),
            Some(((0, BLOCK), 0)),
            "only the peer's block is left, so the mirror races it"
        );
        assert_eq!(join_range(0, &[], &[(0, BLOCK)]), None);
    }

    /// With everything in flight elsewhere, a joining mirror takes the back
    /// half of the longest stretch, so it and the worker on it meet halfway.
    #[test]
    fn a_mirror_with_nothing_unasked_for_splits_the_longest_request() {
        let gaps = [(0, 6 * BLOCK)];
        let others = [(0, BLOCK), (BLOCK, 5 * BLOCK), (5 * BLOCK, 6 * BLOCK)];
        assert_eq!(join_range(0, &gaps, &others), Some(((3 * BLOCK, 5 * BLOCK), 0)));
    }

    #[test]
    fn a_span_is_split_on_a_block_of_its_part() {
        let part = 9_728_000;
        assert_eq!(split_point(part, part, part + 10 * BLOCK), part + 5 * BLOCK);
        assert_eq!(split_point(part, part + 100, part + 3 * BLOCK), part + 2 * BLOCK);
        assert_eq!(split_point(0, 0, BLOCK + BLOCK / 2), BLOCK);
        assert_eq!(split_point(0, 0, BLOCK), 0, "no block boundary past the middle: the whole span");
        assert_eq!(split_point(0, 7, 9), 7);
    }

    /// The report this exists for: a one-part file and two mirrors. The first
    /// claims the part; the second used to find all of it published as in
    /// flight and stream it again from the same offset.
    #[test]
    fn a_second_mirror_on_a_one_part_file_starts_halfway_through_what_is_left() {
        let size = 20 * BLOCK;
        let mut t = tracker(size, "pick");
        let (part, ranges) = pick(&t, 1).expect("a free part");
        assert_eq!((part, ranges.clone()), (0, vec![(0, size)]));
        t.claim_in_progress(0);
        t.publish_in_flight_requests(1, vec![ahead(0, size)]);
        assert_eq!(ahead(0, size), (0, PUBLISHED_AHEAD));

        let (part, ranges) = pick(&t, 2).expect("a share of the held part");
        assert_eq!(part, 0);
        assert_eq!(ranges, vec![(12 * BLOCK, size)], "halfway through what lies past the first mirror's window");
    }

    /// Mirrors on a one-part file, run chunk by chunk as the worker does: the
    /// file comes in once, give or take where they meet, rather than once per
    /// mirror.
    #[test]
    fn mirrors_on_one_part_download_it_about_once_between_them() {
        for mirrors in 2..=5 {
            let size = 40 * BLOCK + 1234;
            let fetched = simulate(&mut tracker(size, &format!("sim{mirrors}")), mirrors);
            assert!(
                fetched <= size + mirrors as u64 * BLOCK,
                "{mirrors} mirrors fetched {fetched} bytes of a {size}-byte file"
            );
        }
    }

    /// A request runs on until it reaches bytes another source wrote.
    #[test]
    fn a_request_stops_where_another_source_wrote() {
        let mut t = tracker(10 * BLOCK, "read-on");
        assert!(read_on(&mut t, 1, BLOCK, 10 * BLOCK));
        assert_eq!(t.requested_by_others(2), vec![(BLOCK, 5 * BLOCK)], "the window ahead is published");
        t.fill_range(2 * BLOCK, 3 * BLOCK);
        assert!(!read_on(&mut t, 1, 2 * BLOCK, 10 * BLOCK));
        assert!(read_on(&mut t, 1, 3 * BLOCK, 10 * BLOCK));
    }

    fn tracker(size: u64, name: &str) -> PartTracker {
        let path = std::env::temp_dir().join(format!("ember-web-worker-test-{name}-{}.part", std::process::id()));
        PartTracker::new(size, &path)
    }

    /// Run `mirrors` mirror workers over `t` in lockstep, one chunk each per
    /// round, picking and stopping as `run_inner` and `stream_body` do.
    /// Returns the bytes they fetched between them.
    fn simulate(t: &mut PartTracker, mirrors: usize) -> u64 {
        // Per mirror: the part it claims, the ranges left of its pass, and
        // where it is reading.
        let mut passes: Vec<Option<(usize, Vec<(u64, u64)>, u64)>> = vec![None; mirrors];
        let mut fetched = 0;
        for _round in 0..10_000 {
            if t.all_complete() {
                return fetched;
            }
            for (worker, pass) in passes.iter_mut().enumerate() {
                if pass.is_none() {
                    if let Some((part, ranges)) = pick(t, worker).filter(|(_, ranges)| !ranges.is_empty()) {
                        t.claim_in_progress(part);
                        t.publish_in_flight_requests(worker, vec![ahead(ranges[0].0, ranges[0].1)]);
                        let start = ranges[0].0;
                        *pass = Some((part, ranges, start));
                    }
                }
                let Some((part, ranges, pos)) = pass.as_mut() else {
                    continue;
                };
                let end = ranges[0].1;
                let chunk_end = end.min(*pos + BLOCK);
                fetched += chunk_end - *pos;
                t.fill_range(*pos, chunk_end);
                *pos = chunk_end;
                let next = if *pos < end && read_on(t, worker, *pos, end) {
                    true
                } else if *pos >= end && ranges.len() > 1 {
                    ranges.remove(0);
                    *pos = ranges[0].0;
                    t.publish_in_flight_requests(worker, vec![ahead(ranges[0].0, ranges[0].1)]);
                    true
                } else {
                    false
                };
                if !next {
                    t.release_in_progress(*part);
                    t.clear_in_flight_requests(worker);
                    *pass = None;
                }
            }
        }
        panic!("{mirrors} mirrors never finished");
    }

    #[test]
    fn only_a_real_content_encoding_counts() {
        assert!(!is_encoded(None));
        for plain in ["identity", " Identity ", "NONE", "none", ""] {
            assert!(!is_encoded(Some(&HeaderValue::from_static(plain))), "{plain:?}");
        }
        for encoded in ["gzip", "br", "deflate", " GZIP "] {
            assert!(is_encoded(Some(&HeaderValue::from_static(encoded))), "{encoded:?}");
        }
    }

    #[test]
    fn content_range_is_read_strictly() {
        assert_eq!(parse_content_range("bytes 0-99/1000"), Some((0, 99, Some(1000))));
        assert_eq!(parse_content_range("bytes 500-999/*"), Some((500, 999, None)));
        assert_eq!(parse_content_range(" bytes 7-7/8 "), Some((7, 7, Some(8))));
        for bad in ["", "bytes */1000", "bytes 9-1/10", "items 0-1/2", "bytes 0-x/2", "bytes 0-1"] {
            assert_eq!(parse_content_range(bad), None, "{bad}");
        }
    }
}
