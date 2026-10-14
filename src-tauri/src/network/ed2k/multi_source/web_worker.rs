//! One web source of a download: fetch the parts no peer is working on with
//! HTTP `Range` requests, into the shared part file.
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

/// Redirects followed per request, each re-validated like the first URL.
const MAX_REDIRECTS: usize = 5;

/// Parts this source may fill that then fail their MD4 before it is retired.
/// One can be bad luck shared with a peer; two from the same mirror is the
/// mirror.
const MAX_BAD_PARTS: u32 = 2;

/// How long to wait when every unfinished part is already being worked on.
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
}

/// Counts its worker in `WebWorker::working` while held.
struct Working {
    count: Arc<std::sync::atomic::AtomicUsize>,
    held: bool,
}

impl Working {
    fn new(count: &Arc<std::sync::atomic::AtomicUsize>) -> Self {
        let mut working = Self { count: count.clone(), held: false };
        working.hold();
        working
    }

    fn hold(&mut self) {
        if !self.held {
            self.count.fetch_add(1, Ordering::Relaxed);
            self.held = true;
        }
    }

    fn release(&mut self) {
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
struct ActiveRequest(Arc<AtomicU32>);

impl ActiveRequest {
    fn new(count: &Arc<AtomicU32>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self(count.clone())
    }
}

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// What this source has written into each part since the part's last verdict,
/// across however many passes it took. A mirror is judged on the bytes it
/// put in the part, not on what one pass happened to carry: a pass can be
/// mostly duplicates, and a mirror that drops every connection fills a part
/// over several.
#[derive(Default)]
struct PartShares(HashMap<usize, PartShare>);

#[derive(Default)]
struct PartShare {
    written: u64,
    /// What the part still lacked when this source last left it. More missing
    /// now means it was reopened since, and what was written before is gone.
    missing_after: u64,
}

impl PartShares {
    fn begin_pass(&mut self, part: usize, missing: u64) {
        if self.0.get(&part).is_some_and(|s| missing > s.missing_after) {
            self.0.remove(&part);
        }
    }

    fn end_pass(&mut self, part: usize, written: u64, missing: u64) {
        let share = self.0.entry(part).or_default();
        share.written = share.written.saturating_add(written);
        share.missing_after = missing;
    }

    /// The bytes to judge a verdict on `part` by; the count starts over.
    fn take(&mut self, part: usize) -> u64 {
        self.0.remove(&part).map_or(0, |s| s.written)
    }
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
        let mut shares = PartShares::default();
        let mut bad_parts: u32 = 0;
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
            let picked = {
                let mut t = self.tracker.write().await;
                let claimed = t.in_progress_flags();
                let part = (0..t.part_count).find(|&p| {
                    !t.is_part_complete(p) && !claimed.get(p).copied().unwrap_or(false)
                });
                part.map(|p| {
                    guard.claim_locked(p, &mut t);
                    let (ps, pe) = t.part_range(p);
                    (p, t.fillable_subranges(ps, pe))
                })
            };
            let Some((part, gaps)) = picked else {
                // Every unfinished part has a peer on it. Wait, rather than
                // racing them for the same bytes.
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

            shares.begin_pass(part, gaps.iter().map(|&(gs, ge)| ge - gs).sum());
            // So a peer worker piling onto this part in the endgame asks for
            // these ranges last, as it does for another peer's requests.
            let in_flight: Vec<OutstandingRange> =
                gaps.iter().map(|&(gs, ge)| OutstandingRange::new(gs, ge)).collect();
            guard.publish_in_flight(&in_flight, None).await;
            let mut written: u64 = 0;
            let mut outcome: Result<(), FetchError> = Ok(());
            for (gs, ge) in gaps {
                match self
                    .fetch_range(&mut effective_url, gs, ge, &mut transferred, &mut written)
                    .await
                {
                    Ok(()) => {}
                    Err(e) => {
                        outcome = Err(e);
                        break;
                    }
                }
            }
            guard.publish_in_flight(&[], None).await;
            // Check what this source just filled now, while the claim still
            // keeps the sweep and every peer off it, so the verdict is about
            // this mirror and a bad one is found out after one part.
            let to_check = {
                let t = self.tracker.read().await;
                let (ps, pe) = t.part_range(part);
                let missing = t.fillable_subranges(ps, pe).iter().map(|&(gs, ge)| ge - gs).sum();
                shares.end_pass(part, written, missing);
                (outcome.is_ok() && t.is_part_complete(part) && !t.is_part_verified(part))
                    .then(|| ((ps, pe), t.part_content_generation(part)))
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
                Ok(()) => web_sources::note_success(&self.file_hash, &self.url),
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

            // Held against the mirror only when it supplied most of the part:
            // one a peer had mostly filled says little about the mirror.
            let supplied = match &checked {
                Some((_, ClaimedPartCheck::Unreadable)) | None => 0,
                Some(_) => shares.take(part),
            };
            if let Some(((ps, pe), ClaimedPartCheck::Corrupt)) = checked {
                if supplied.saturating_mul(2) >= pe - ps {
                    bad_parts += 1;
                    warn!(
                        "Part {part} from web source {} failed verification ({bad_parts} so far)",
                        self.url
                    );
                    if bad_parts >= MAX_BAD_PARTS {
                        web_sources::note_failure(&self.file_hash, &self.url, true);
                        self.report("failed", 0, transferred, Some(SourceFailureKind::Permanent))
                            .await;
                        return Ok(());
                    }
                }
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
            if !web_sources::urls(&self.file_hash).contains(&self.url)
                || web_sources::is_retired(&self.file_hash, &self.url)
            {
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
    ) -> Result<(), FetchError> {
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
    ) -> Result<(), FetchError> {
        let wire = self.tracker.read().await.transferred_counter();
        let mut pos = body_start;
        let mut buf: Vec<u8> = Vec::with_capacity(WRITE_CHUNK);
        let mut window_start = std::time::Instant::now();
        let mut window_bytes: u64 = 0;
        let mut reported_transferring = false;
        let mut got_any = false;
        loop {
            if !web_sources::enabled() {
                // Switched off mid-request. What was written stays; the worker
                // ends at the top of its loop rather than after a whole part.
                return Ok(());
            }
            let chunk = tokio::select! {
                c = response.chunk() => c.map_err(|e| FetchError::Transient(format!("read failed: {e}")))?,
                _ = self.control.wait_cancel_or_pause() => {
                    return Err(FetchError::Stopped(anyhow::anyhow!("cancelled by user")));
                }
            };
            let done = chunk.is_none();
            if let Some(bytes) = chunk {
                let room = end.saturating_sub(pos + buf.len() as u64) as usize;
                buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
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
                if outcome.newly_written > 0 {
                    let _ = self
                        .progress_tx
                        .try_send((self.worker, outcome.newly_written as i64));
                }
                got_any = true;
                pos += len;
                buf.clear();
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
                return Ok(());
            }
            if done {
                // Short body: what came is written, and the gap map says what
                // is left. Nothing at all is a failure.
                return if got_any {
                    Ok(())
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
    use super::{is_encoded, parse_content_range, PartShares};
    use reqwest::header::HeaderValue;

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
    fn a_mirror_is_judged_on_what_it_wrote_across_passes() {
        let mut shares = PartShares::default();
        // Two passes that each dropped early, then one that finished.
        shares.begin_pass(0, 100);
        shares.end_pass(0, 30, 70);
        shares.begin_pass(0, 70);
        shares.end_pass(0, 30, 40);
        shares.begin_pass(0, 40);
        shares.end_pass(0, 0, 0);
        assert_eq!(shares.take(0), 60, "duplicates add nothing, earlier passes count");
        assert_eq!(shares.take(0), 0, "a verdict starts the count over");

        // Reopened since this source last left it: what it wrote is gone.
        shares.begin_pass(1, 100);
        shares.end_pass(1, 80, 20);
        shares.begin_pass(1, 100);
        shares.end_pass(1, 10, 0);
        assert_eq!(shares.take(1), 10);
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
