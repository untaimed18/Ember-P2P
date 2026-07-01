use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::dead_sources::{
    FILEREASKTIME_SECS, KAD_CALLBACK_REASK_SECS, SOURCECLIENTREASKS_SECS as SOURCECLIENTREASKS_I64,
};
use super::messages::build_answer_sources1_versioned;
use super::transfer::is_filtered_source_ip;

const MAX_SOURCES_PER_FILE: usize = 500;
const SOURCE_EXPIRY_SECS: i64 = 3600;
const MAX_SOURCES_IN_RESPONSE: usize = 500;
const MAX_TRACKED_FILES: usize = 500;

/// eMule: minimum gap between TCP connection attempts to the same source (20 min)
const MIN_TCP_RECONNECT_SECS: i64 = 1200;

/// Whether a stored source may be forwarded in an OP_ANSWERSOURCES(2) reply.
///
/// Matches eMule's `CreateSrcInfoPacket`: HighID sources are gated on a valid,
/// non-filtered IP that isn't the requester; LowID (firewalled) sources are
/// forwarded too — eMule includes them so the receiver can reach them via a
/// server callback — but only when they carry a usable server reference (their
/// own IP is unknown, so the IP-based filters don't apply to them).
pub(crate) fn sx_answer_source_eligible(e: &SourceEntry, exclude_ip: Ipv4Addr, now: i64) -> bool {
    if now.saturating_sub(e.last_seen) >= SOURCE_EXPIRY_SECS {
        return false;
    }
    if e.client_id != 0 {
        e.server_ip != 0 && e.server_port != 0
    } else {
        e.ip != exclude_ip && !is_filtered_source_ip(&e.ip)
    }
}

/// The eMule "hybrid" (host-order) source ID to advertise for a source: the
/// LowID server-assigned client id for firewalled sources, otherwise the
/// host-order IP. Callers byte-swap this for SX versions < 3 (matching
/// `CreateSrcInfoPacket`'s `htonl`) and send it verbatim for v >= 3.
pub(crate) fn sx_answer_source_id(src: &SourceEntry) -> u32 {
    if src.client_id != 0 {
        src.client_id
    } else {
        u32::from(src.ip)
    }
}

// ---------------------------------------------------------------------------
// Per-file download source list  (eMule CPartFile::srclist equivalent)
// ---------------------------------------------------------------------------

/// eMule download-source state machine (DS_* in DownloadClient.h).
#[derive(Debug, Clone)]
pub enum DownloadSourceState {
    /// Discovered but not yet contacted (DS_NONE).
    New,
    /// TCP connection in progress (DS_CONNECTING).
    Connecting,
    /// Waiting for an upload slot on the remote peer (DS_ONQUEUE).
    OnQueue { rank: Option<u32> },
    /// Actively receiving data (DS_DOWNLOADING).
    Downloading,
    /// Peer has no parts we still need (DS_NONEEDEDPARTS).
    NoneNeededParts,
    /// Transient failure (DS_ERROR). Reasked after FILEREASKTIME.
    Failed,
    /// Waiting for Low-ID callback via server (DS_WAITCALLBACK).
    WaitCallback,
    /// Waiting for Low-ID callback via Kad buddy (DS_WAITCALLBACKKAD).
    WaitCallbackKad,
    /// Too many connections, retry later (DS_TOOMANYCONNS).
    TooManyConns,
    /// Both sides are Low-ID, cannot connect (DS_LOWTOLOWIP).
    LowToLowIp,
    /// Both sides are Low-ID, but Ember relay/hole-punch is being attempted.
    EmberRelay,
    /// Banned by remote peer (DS_BANNED).
    Banned,
}

/// A single download source tracked across connection attempts.
#[derive(Debug, Clone)]
pub struct DownloadSourceEntry {
    pub ip: Ipv4Addr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub state: DownloadSourceState,
    /// When we last sent a file request / reask to this source.
    pub last_asked: Instant,
    /// When we last sent a UDP `OP_REASKFILEPING` to this source. Tracked
    /// separately from `last_asked` so a UDP reask does NOT push out the
    /// `MIN_TCP_RECONNECT_SECS` (20 min) TCP-reconnect gate in
    /// `can_try_tcp_at` — previously `mark_udp_reask_sent` bumped
    /// `last_asked`, silently delaying the next TCP attempt by 20 minutes.
    pub last_udp_reask: Instant,
    /// When the state last changed (for timeout decisions).
    pub state_changed: Instant,
    /// Number of consecutive failures without a successful data transfer.
    pub fail_count: u32,
    /// KAD callback buddy IP (`TAG_SERVERIP` on type-3/5 source publishes).
    pub callback_buddy_ip: Option<Ipv4Addr>,
    /// KAD callback buddy UDP port (`TAG_SERVERPORT`).
    pub callback_buddy_port: Option<u16>,
    /// KAD callback verification token (`TAG_BUDDYHASH` = NOT LowID peer KAD id).
    pub callback_buddy_hash: Option<[u8; 16]>,
    /// Publisher's ED2K user hash from the KAD source record.
    pub source_user_hash: Option<[u8; 16]>,
    /// Latest part availability bitmap learned from TCP file status or UDP
    /// OP_REASKACK. Used for NNP and complete-source accounting.
    pub available_parts: Vec<bool>,
}

impl DownloadSourceEntry {
    pub fn new(ip: Ipv4Addr, tcp_port: u16) -> Self {
        let now = Instant::now();
        Self {
            ip,
            tcp_port,
            udp_port: 0,
            state: DownloadSourceState::New,
            last_asked: now,
            last_udp_reask: now,
            state_changed: now,
            fail_count: 0,
            callback_buddy_ip: None,
            callback_buddy_port: None,
            callback_buddy_hash: None,
            source_user_hash: None,
            available_parts: Vec::new(),
        }
    }

    /// Shift `last_asked` so [`Self::time_until_reask`] returns 0 immediately.
    fn arm_callback_reask(&mut self) {
        self.last_asked = Instant::now()
            .checked_sub(Duration::from_secs(FILEREASKTIME_SECS as u64 + 1))
            .unwrap_or_else(Instant::now);
    }

    /// Whether a KAD `CallbackReq` should be (re)sent for this firewalled
    /// source. Uses the short [`KAD_CALLBACK_REASK_SECS`] cadence rather than
    /// the ~29-minute `FILEREASKTIME` used by [`Self::time_until_reask`] for
    /// other states, so a lost callback is retried promptly. Gated on having
    /// buddy info so we never spin on a source we can't actually call back.
    pub fn kad_callback_reask_due(&self) -> bool {
        matches!(self.state, DownloadSourceState::WaitCallbackKad)
            && self.callback_buddy_ip.is_some()
            && self.last_asked.elapsed().as_secs() >= KAD_CALLBACK_REASK_SECS as u64
    }

    /// D10: maximum wall time a source is allowed to sit in `Connecting`
    /// (or `Downloading`) before we consider the driving task dead and
    /// reconsider the source. A healthy TCP handshake plus hashset
    /// exchange is comfortably under a minute; anything longer is a
    /// stuck slot or an aborted task. 120 s gives generous slack.
    const CONNECTING_WATCHDOG_SECS: u64 = 120;

    /// eMule GetTimeUntilReask(): seconds until this source should be reasked.
    /// Returns 0 when the source is ready for a new connection attempt.
    pub fn time_until_reask(&self) -> u64 {
        self.time_until_reask_at(Instant::now())
    }

    fn time_until_reask_at(&self, now: Instant) -> u64 {
        let interval = match &self.state {
            DownloadSourceState::New => return 0,
            DownloadSourceState::NoneNeededParts => (FILEREASKTIME_SECS * 2) as u64,
            DownloadSourceState::Failed | DownloadSourceState::TooManyConns => {
                FILEREASKTIME_SECS as u64
            }
            DownloadSourceState::OnQueue { .. } => FILEREASKTIME_SECS as u64,
            DownloadSourceState::WaitCallback | DownloadSourceState::WaitCallbackKad => {
                FILEREASKTIME_SECS as u64
            }
            DownloadSourceState::Connecting | DownloadSourceState::Downloading => {
                // Watchdog: if a source has been `Connecting` /
                // `Downloading` far longer than any legitimate handshake
                // or transfer gap, treat it as stuck and allow a fresh
                // reask. Without this, a panicked or killed driver task
                // leaves the source permanently "active" and the
                // scheduler can't pick it up again until the next full
                // list reset.
                if now.saturating_duration_since(self.state_changed).as_secs()
                    >= Self::CONNECTING_WATCHDOG_SECS
                {
                    return 0;
                }
                return u64::MAX;
            }
            DownloadSourceState::LowToLowIp
            | DownloadSourceState::EmberRelay
            | DownloadSourceState::Banned => return u64::MAX,
        };
        let elapsed = now.saturating_duration_since(self.last_asked).as_secs();
        interval.saturating_sub(elapsed)
    }

    /// Whether enough time has passed since the last TCP attempt.
    pub fn can_try_tcp(&self) -> bool {
        self.can_try_tcp_at(Instant::now())
    }

    fn can_try_tcp_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_asked).as_secs() >= MIN_TCP_RECONNECT_SECS as u64
            || matches!(self.state, DownloadSourceState::New)
    }

    /// Whether this source should receive a UDP reask ping
    /// (27 min after last ask, i.e. 2 min before FILEREASKTIME).
    pub fn needs_udp_reask(&self) -> bool {
        if self.udp_port == 0 {
            return false;
        }
        // Gate on the most recent ask of EITHER kind so we neither spam UDP
        // reasks nor reask right after a TCP ask, while keeping the TCP
        // reconnect gate (`can_try_tcp_at`) keyed only on `last_asked`.
        let last = self.last_asked.max(self.last_udp_reask);
        let elapsed = last.elapsed().as_secs();
        let threshold = (FILEREASKTIME_SECS - 120).max(0) as u64;
        matches!(
            self.state,
            DownloadSourceState::OnQueue { .. } | DownloadSourceState::Failed
        ) && elapsed >= threshold
    }
}

/// Persistent source list for a single file download.
/// Mirrors eMule's `CPartFile::srclist`.
#[derive(Debug)]
pub struct PerFileSourceList {
    pub file_hash: [u8; 16],
    pub sources: Vec<DownloadSourceEntry>,
}

impl PerFileSourceList {
    pub fn new(file_hash: [u8; 16]) -> Self {
        Self {
            file_hash,
            sources: Vec::new(),
        }
    }

    pub fn file_hash(&self) -> [u8; 16] {
        self.file_hash
    }

    pub fn has_source(&self, ip: Ipv4Addr, tcp_port: u16) -> bool {
        self.sources
            .iter()
            .any(|s| s.ip == ip && s.tcp_port == tcp_port)
    }

    pub fn add_source_full(&mut self, ip: Ipv4Addr, tcp_port: u16, udp_port: u16) -> bool {
        self.add_source_with_identity(ip, tcp_port, udp_port, None)
    }

    /// Register a KAD callback source. Firewalled type 3/5 publishes omit
    /// `TAG_SOURCEIP`, so deduplicate by publisher user hash when present —
    /// then fall back to IP:port so the same peer reported by both KAD and
    /// the connected server (KAD with hash, server without) doesn't get
    /// double-inserted as two separate rows.
    pub fn add_source_with_identity(
        &mut self,
        ip: Ipv4Addr,
        tcp_port: u16,
        udp_port: u16,
        user_hash: Option<[u8; 16]>,
    ) -> bool {
        if self.sources.len() >= MAX_SOURCES_PER_FILE {
            return false;
        }
        let uh_opt = user_hash.filter(|h| *h != [0u8; 16]);

        // Dedup by user hash first (catches type 3/5 publishes that omit
        // TAG_SOURCEIP — user hash is the only stable identity).
        if let Some(uh) = uh_opt {
            if let Some(existing) = self
                .sources
                .iter_mut()
                .find(|s| s.source_user_hash == Some(uh))
            {
                if udp_port > 0 {
                    existing.udp_port = udp_port;
                }
                if !ip.is_unspecified() && existing.ip.is_unspecified() {
                    existing.ip = ip;
                    existing.tcp_port = tcp_port;
                }
                return false;
            }
        }

        // Dedup by IP:port (only meaningful when IP is specified). Backfills
        // `source_user_hash` if we previously learned the peer without one.
        if !ip.is_unspecified() {
            if let Some(existing) = self
                .sources
                .iter_mut()
                .find(|s| s.ip == ip && s.tcp_port == tcp_port)
            {
                if udp_port > 0 {
                    existing.udp_port = udp_port;
                }
                if let Some(uh) = uh_opt {
                    if existing.source_user_hash.is_none() {
                        existing.source_user_hash = Some(uh);
                    }
                }
                return false;
            }
        }

        let mut entry = DownloadSourceEntry::new(ip, tcp_port);
        entry.udp_port = udp_port;
        entry.source_user_hash = uh_opt;
        self.sources.push(entry);
        true
    }

    /// Mark a source as having started a connection attempt.
    pub fn set_connecting(&mut self, ip: Ipv4Addr, port: u16) {
        if let Some(s) = self.find_mut(ip, port) {
            s.state = DownloadSourceState::Connecting;
            s.last_asked = Instant::now();
            s.state_changed = Instant::now();
        }
    }

    /// Mark a source as queued (received OP_QUEUERANKING).
    pub fn set_on_queue(&mut self, ip: Ipv4Addr, port: u16, rank: Option<u32>) {
        if let Some(s) = self.find_mut(ip, port) {
            s.state = DownloadSourceState::OnQueue { rank };
            s.state_changed = Instant::now();
            s.fail_count = s.fail_count.saturating_sub(1);
        }
    }

    /// Mark a source as actively transferring.
    pub fn set_downloading(&mut self, ip: Ipv4Addr, port: u16) {
        if let Some(s) = self.find_mut(ip, port) {
            s.state = DownloadSourceState::Downloading;
            s.state_changed = Instant::now();
            s.fail_count = 0;
        }
    }

    /// Record a weighted failure for a source. Queue progress and successful
    /// transfers will decay this score over time.
    pub fn set_failed_with_penalty(&mut self, ip: Ipv4Addr, port: u16, penalty: u32) {
        if let Some(s) = self.find_mut(ip, port) {
            s.state = DownloadSourceState::Failed;
            s.state_changed = Instant::now();
            s.fail_count = s.fail_count.saturating_add(penalty.max(1));
        }
    }

    /// Mark a source as having no needed parts.
    pub fn set_none_needed_parts(&mut self, ip: Ipv4Addr, port: u16) {
        if let Some(s) = self.find_mut(ip, port) {
            s.state = DownloadSourceState::NoneNeededParts;
            s.state_changed = Instant::now();
            s.fail_count = s.fail_count.saturating_sub(1);
        }
    }

    /// Mark a source as waiting for Low-ID callback via server.
    pub fn set_wait_callback(&mut self, ip: Ipv4Addr, port: u16) {
        if let Some(s) = self.find_mut(ip, port) {
            s.state = DownloadSourceState::WaitCallback;
            s.state_changed = Instant::now();
        }
    }

    /// Mark a source as waiting for Low-ID callback via Kad buddy.
    pub fn set_wait_callback_kad(&mut self, ip: Ipv4Addr, port: u16) {
        if let Some(s) = self.find_mut(ip, port) {
            s.state = DownloadSourceState::WaitCallbackKad;
            s.state_changed = Instant::now();
        }
    }

    /// Record KAD callback buddy metadata and transition to `WaitCallbackKad`.
    /// When `is_new`, arms an immediate first `CallbackReq`; rediscoveries only
    /// update buddy fields without resetting the reask timer.
    pub fn set_kad_callback_buddy(
        &mut self,
        ip: Ipv4Addr,
        port: u16,
        buddy_ip: Ipv4Addr,
        buddy_port: u16,
        buddy_hash: [u8; 16],
        source_user_hash: Option<[u8; 16]>,
        is_new: bool,
    ) {
        let target_idx = if ip.is_unspecified() {
            source_user_hash.and_then(|uh| {
                self.sources
                    .iter()
                    .position(|s| s.source_user_hash == Some(uh))
            })
        } else {
            self.sources
                .iter()
                .position(|s| s.ip == ip && s.tcp_port == port)
        };
        if let Some(idx) = target_idx {
            let s = &mut self.sources[idx];
            s.callback_buddy_ip = Some(buddy_ip);
            s.callback_buddy_port = Some(buddy_port);
            s.callback_buddy_hash = Some(buddy_hash);
            if source_user_hash.is_some() {
                s.source_user_hash = source_user_hash;
            }
            s.state = DownloadSourceState::WaitCallbackKad;
            s.state_changed = Instant::now();
            if is_new {
                s.arm_callback_reask();
            }
        }
    }

    /// Whether a KAD callback `CallbackReq` should be sent now.
    pub fn callback_reask_due(&self, ip: Ipv4Addr, port: u16) -> bool {
        self.find(ip, port)
            .map(|s| s.kad_callback_reask_due())
            .unwrap_or(false)
    }

    /// Bump the reask timer after a successful `CallbackReq` send.
    pub fn mark_callback_requested(&mut self, ip: Ipv4Addr, port: u16) {
        if let Some(s) = self.find_mut(ip, port) {
            s.last_asked = Instant::now();
        }
    }

    /// Both sides are Low-ID; direct connection is impossible.
    pub fn set_low_to_low(&mut self, ip: Ipv4Addr, port: u16) {
        if let Some(s) = self.find_mut(ip, port) {
            s.state = DownloadSourceState::LowToLowIp;
            s.state_changed = Instant::now();
        }
    }

    /// Both sides are Low-ID but Ember relay/hole-punch is being attempted.
    pub fn set_ember_relay(&mut self, ip: Ipv4Addr, port: u16) {
        if let Some(s) = self.find_mut(ip, port) {
            s.state = DownloadSourceState::EmberRelay;
            s.state_changed = Instant::now();
        }
    }

    /// Remote peer has banned us.
    pub fn set_banned(&mut self, ip: Ipv4Addr, port: u16) {
        if let Some(s) = self.find_mut(ip, port) {
            s.state = DownloadSourceState::Banned;
            s.state_changed = Instant::now();
        }
    }

    /// Too many concurrent connections; retry later.
    pub fn set_too_many_conns(&mut self, ip: Ipv4Addr, port: u16) {
        if let Some(s) = self.find_mut(ip, port) {
            s.state = DownloadSourceState::TooManyConns;
            s.state_changed = Instant::now();
        }
    }

    /// Sources ready for a new TCP connection attempt (reask timer expired).
    /// Sorted by quality: queued sources first (by rank), then by fail count
    /// so that reliable sources are tried before repeatedly-failing ones.
    ///
    /// **Important:** This does not filter against `DeadSourceList`. Callers MUST
    /// filter the returned sources through `DeadSourceList::is_dead_source_for_file`
    /// before initiating connections.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn sources_ready_for_reask(&self) -> Vec<(Ipv4Addr, u16)> {
        self.sources_ready_for_reask_at(Instant::now())
    }

    #[cfg(test)]
    fn sources_ready_for_reask_at(&self, now: Instant) -> Vec<(Ipv4Addr, u16)> {
        let mut ready: Vec<&DownloadSourceEntry> = self
            .sources
            .iter()
            .filter(|s| {
                s.time_until_reask_at(now) == 0
                    && s.can_try_tcp_at(now)
                    && !matches!(
                        s.state,
                        DownloadSourceState::Banned
                            | DownloadSourceState::LowToLowIp
                            | DownloadSourceState::EmberRelay
                    )
            })
            .collect();
        ready.sort_by(|a, b| {
            let rank_a = match &a.state {
                DownloadSourceState::OnQueue { rank } => rank.unwrap_or(u32::MAX),
                _ => u32::MAX,
            };
            let rank_b = match &b.state {
                DownloadSourceState::OnQueue { rank } => rank.unwrap_or(u32::MAX),
                _ => u32::MAX,
            };
            rank_a
                .cmp(&rank_b)
                .then_with(|| a.fail_count.cmp(&b.fail_count))
        });
        ready.into_iter().map(|s| (s.ip, s.tcp_port)).collect()
    }

    /// Like `sources_ready_for_reask` but factors in reputation scores
    /// and filters out reputation-banned peers.
    pub fn sources_ready_for_reask_with_reputation<F>(
        &self,
        is_banned: F,
        score_fn: impl Fn(Ipv4Addr, u16) -> i32,
    ) -> Vec<(Ipv4Addr, u16)>
    where
        F: Fn(Ipv4Addr, u16) -> bool,
    {
        let mut ready: Vec<&DownloadSourceEntry> = self
            .sources
            .iter()
            .filter(|s| {
                s.time_until_reask() == 0
                    && s.can_try_tcp()
                    && !matches!(
                        s.state,
                        DownloadSourceState::Banned
                            | DownloadSourceState::LowToLowIp
                            | DownloadSourceState::EmberRelay
                    )
                    && !is_banned(s.ip, s.tcp_port)
            })
            .collect();
        ready.sort_by(|a, b| {
            let rank_a = match &a.state {
                DownloadSourceState::OnQueue { rank } => rank.unwrap_or(u32::MAX),
                _ => u32::MAX,
            };
            let rank_b = match &b.state {
                DownloadSourceState::OnQueue { rank } => rank.unwrap_or(u32::MAX),
                _ => u32::MAX,
            };
            rank_a
                .cmp(&rank_b)
                .then_with(|| a.fail_count.cmp(&b.fail_count))
                .then_with(|| {
                    let rep_a = score_fn(a.ip, a.tcp_port);
                    let rep_b = score_fn(b.ip, b.tcp_port);
                    rep_b.cmp(&rep_a)
                })
        });
        ready.into_iter().map(|s| (s.ip, s.tcp_port)).collect()
    }

    /// Sources that need a UDP reask ping (~27 min after last ask).
    pub fn sources_needing_udp_reask(&self) -> Vec<(Ipv4Addr, u16, u16)> {
        self.sources
            .iter()
            .filter(|s| s.needs_udp_reask())
            .map(|s| (s.ip, s.tcp_port, s.udp_port))
            .collect()
    }

    /// Bump `last_asked` on the matching source so the next
    /// `needs_udp_reask()` call returns false until another full
    /// `FILEREASKTIME_SECS - 120` window elapses. Without this, the
    /// source stays "due" forever and the 5s reask timer in the
    /// network event loop emits a fresh `OP_REASKFILEPING` on every
    /// tick — peers throttle/ban the IP and we self-DoS our own
    /// upstream.
    pub fn mark_udp_reask_sent(&mut self, ip: Ipv4Addr, tcp_port: u16) {
        if let Some(s) = self.find_mut(ip, tcp_port) {
            s.last_udp_reask = std::time::Instant::now();
        }
    }

    /// Count sources with a full availability bitmap (eMule: m_nCompleteSourcesCount).
    pub fn complete_source_count(&self) -> u16 {
        self.sources
            .iter()
            .filter(|s| !s.available_parts.is_empty() && s.available_parts.iter().all(|have| *have))
            .count()
            .min(u16::MAX as usize) as u16
    }

    pub fn apply_udp_reask_ack(
        &mut self,
        ip: Ipv4Addr,
        udp_port: u16,
        rank: Option<u16>,
        available_parts: Option<Vec<bool>>,
    ) {
        if let Some(s) = self
            .sources
            .iter_mut()
            .find(|s| s.ip == ip && s.udp_port == udp_port)
        {
            if let Some(parts) = available_parts {
                s.available_parts = parts;
                if rank.is_some() {
                    s.state = DownloadSourceState::OnQueue {
                        rank: rank.map(u32::from),
                    };
                } else if !s.available_parts.iter().any(|have| *have) {
                    s.state = DownloadSourceState::NoneNeededParts;
                } else {
                    s.state = DownloadSourceState::OnQueue { rank: None };
                }
            } else {
                s.state = DownloadSourceState::OnQueue {
                    rank: rank.map(u32::from),
                };
            }
            s.state_changed = std::time::Instant::now();
            s.fail_count = s.fail_count.saturating_sub(1);
        }
    }

    /// Remove persistently bad sources after repeated failures.
    pub fn purge_dead_sources(&mut self) {
        self.sources.retain(|s| s.fail_count <= 8);
    }

    /// Reset sources stuck in Connecting/Downloading back to Failed so they
    /// become re-askable after the normal FILEREASKTIME cooldown.  Called when
    /// a download task ends (failure or pause) to prevent sources from being
    /// permanently unreachable on retry/resume.
    pub fn reset_active_states(&mut self) {
        for s in &mut self.sources {
            if matches!(
                s.state,
                DownloadSourceState::Connecting | DownloadSourceState::Downloading
            ) {
                s.state = DownloadSourceState::Failed;
                s.state_changed = std::time::Instant::now();
            }
        }
    }

    fn find(&self, ip: Ipv4Addr, port: u16) -> Option<&DownloadSourceEntry> {
        self.sources
            .iter()
            .find(|s| s.ip == ip && s.tcp_port == port)
    }

    fn find_mut(&mut self, ip: Ipv4Addr, port: u16) -> Option<&mut DownloadSourceEntry> {
        self.sources
            .iter_mut()
            .find(|s| s.ip == ip && s.tcp_port == port)
    }
}

#[derive(Debug, Clone)]
pub struct SourceEntry {
    pub ip: Ipv4Addr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub server_ip: u32,
    pub server_port: u16,
    pub last_seen: i64,
    pub user_hash: [u8; 16],
    pub connect_options: u8,
    /// LowID server-assigned client ID (0 = HighID, connectable directly)
    pub client_id: u32,
    /// Timestamp of last OP_REASKFILEPING sent to this source (0 = never asked)
    pub last_asked: i64,
    /// When we last sent OP_REQUESTSOURCES to this source (0 = never)
    pub last_sx_sent: i64,
    /// When we last sent OP_CALLBACKREQUEST for this LowID source (0 = never)
    pub last_callback_at: i64,
}

/// Tracks known sources (peers) per file hash for source exchange responses.
#[derive(Debug)]
pub struct SourceManager {
    sources: HashMap<[u8; 16], Vec<SourceEntry>>,
    max_per_file: usize,
}

impl Default for SourceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceManager {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            max_per_file: MAX_SOURCES_PER_FILE,
        }
    }

    pub fn set_max_per_file(&mut self, max: u32) {
        self.max_per_file = (max as usize).max(50);
    }

    pub fn register_source(&mut self, file_hash: [u8; 16], ip: Ipv4Addr, tcp_port: u16) {
        self.register_source_with_hash(file_hash, ip, tcp_port, [0u8; 16]);
    }

    pub fn register_source_with_hash(
        &mut self,
        file_hash: [u8; 16],
        ip: Ipv4Addr,
        tcp_port: u16,
        user_hash: [u8; 16],
    ) {
        self.register_source_full(file_hash, ip, tcp_port, 0, user_hash);
    }

    pub fn register_source_full(
        &mut self,
        file_hash: [u8; 16],
        ip: Ipv4Addr,
        tcp_port: u16,
        udp_port: u16,
        user_hash: [u8; 16],
    ) {
        self.register_source_full_opts(file_hash, ip, tcp_port, udp_port, user_hash, 0);
    }

    pub fn register_source_full_opts(
        &mut self,
        file_hash: [u8; 16],
        ip: Ipv4Addr,
        tcp_port: u16,
        udp_port: u16,
        user_hash: [u8; 16],
        connect_options: u8,
    ) {
        self.register_source_full_server(
            file_hash,
            ip,
            tcp_port,
            udp_port,
            0,
            0,
            user_hash,
            connect_options,
        );
    }

    pub fn register_source_full_server(
        &mut self,
        file_hash: [u8; 16],
        ip: Ipv4Addr,
        tcp_port: u16,
        udp_port: u16,
        server_ip: u32,
        server_port: u16,
        user_hash: [u8; 16],
        connect_options: u8,
    ) {
        let now = chrono::Utc::now().timestamp();
        let entries = self.sources.entry(file_hash).or_default();

        if let Some(existing) = entries
            .iter_mut()
            .find(|e| e.ip == ip && e.tcp_port == tcp_port)
        {
            existing.last_seen = now;
            if user_hash != [0u8; 16] {
                existing.user_hash = user_hash;
            }
            if udp_port > 0 {
                existing.udp_port = udp_port;
            }
            if server_ip != 0 {
                existing.server_ip = server_ip;
            }
            if server_port != 0 {
                existing.server_port = server_port;
            }
            if connect_options != 0 {
                existing.connect_options = connect_options;
            }
            return;
        }

        if entries.len() >= self.max_per_file {
            entries.sort_by_key(|e| e.last_seen);
            entries.remove(0);
        }

        entries.push(SourceEntry {
            ip,
            tcp_port,
            udp_port,
            server_ip,
            server_port,
            last_seen: now,
            user_hash,
            connect_options,
            client_id: 0,
            last_asked: 0,
            last_sx_sent: 0,
            last_callback_at: 0,
        });

        if self.sources.len() > MAX_TRACKED_FILES {
            self.cleanup_expired();
        }
    }

    /// Look up the user_hash for a source by IP:port across all tracked files.
    pub fn find_user_hash_by_addr(&self, ip: Ipv4Addr, port: u16) -> Option<[u8; 16]> {
        for entries in self.sources.values() {
            for e in entries {
                if e.ip == ip && e.tcp_port == port && e.user_hash != [0u8; 16] {
                    return Some(e.user_hash);
                }
            }
        }
        None
    }

    /// Return the single eD2k user hash associated with `ip` across all tracked
    /// files, or `None` if the IP is unknown, has no hashed entry, or maps to
    /// *more than one* distinct identity (i.e. multiple peers behind the same
    /// NAT — we can't safely attribute a live connection to one of them by IP
    /// alone). Used to stamp a live source row with its peer identity even when
    /// the live connection landed on the peer's ephemeral outbound port
    /// (different from the listening port we tracked), so duplicate rows for
    /// the same peer can be coalesced (mirrors eMule keying a client by hash).
    ///
    /// Only *non-expired* entries are considered: a stale hash left over from a
    /// previous peer that held this IP (e.g. reloaded from `sources.met`, or an
    /// entry whose peer left and whose address was reassigned) must not be
    /// attributed to whoever holds the IP now, or we could mis-stamp a live
    /// connection and merge two distinct peers.
    pub fn unique_user_hash_for_ip(&self, ip: Ipv4Addr) -> Option<[u8; 16]> {
        let now = chrono::Utc::now().timestamp();
        let mut found: Option<[u8; 16]> = None;
        for entries in self.sources.values() {
            for e in entries {
                if e.ip == ip
                    && e.user_hash != [0u8; 16]
                    && now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS
                {
                    match found {
                        None => found = Some(e.user_hash),
                        Some(h) if h == e.user_hash => {}
                        Some(_) => return None,
                    }
                }
            }
        }
        found
    }

    /// Look up all known IPs for a given user_hash across all tracked files.
    pub fn find_ips_by_user_hash(&self, user_hash: &[u8; 16]) -> Vec<Ipv4Addr> {
        let mut ips = Vec::new();
        for entries in self.sources.values() {
            for e in entries {
                if &e.user_hash == user_hash && !ips.contains(&e.ip) {
                    ips.push(e.ip);
                }
            }
        }
        ips
    }

    pub fn build_answer_sources2_versioned(
        &self,
        file_hash: &[u8; 16],
        exclude_ip: Ipv4Addr,
        requested_version: u8,
    ) -> Vec<u8> {
        let now = chrono::Utc::now().timestamp();
        let version: u8 = requested_version.clamp(1, 4);

        let mut sources: Vec<&SourceEntry> = self
            .sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| sx_answer_source_eligible(e, exclude_ip, now))
                    .collect()
            })
            .unwrap_or_default();
        sources.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        sources.truncate(MAX_SOURCES_IN_RESPONSE);

        let entry_size = match version {
            1 => 12,
            2 | 3 => 28,
            _ => 29,
        };
        let mut resp = Vec::with_capacity(1 + 16 + 2 + sources.len() * entry_size);
        resp.push(version);
        resp.extend_from_slice(file_hash);
        resp.extend_from_slice(&(sources.len() as u16).to_le_bytes());
        for src in &sources {
            let id_value = sx_answer_source_id(src);
            if version >= 3 {
                resp.extend_from_slice(&id_value.to_le_bytes());
            } else {
                resp.extend_from_slice(&id_value.to_be_bytes());
            }
            resp.extend_from_slice(&src.tcp_port.to_le_bytes());
            resp.extend_from_slice(&src.server_ip.to_le_bytes());
            resp.extend_from_slice(&src.server_port.to_le_bytes());
            if version >= 2 {
                resp.extend_from_slice(&src.user_hash);
            }

            if version >= 4 {
                resp.push(src.connect_options);
            }
        }

        resp
    }

    /// Build a legacy OP_ANSWERSOURCES (v1) response.
    pub fn build_answer_sources1_versioned(
        &self,
        file_hash: &[u8; 16],
        exclude_ip: Ipv4Addr,
        requested_version: u8,
    ) -> Vec<u8> {
        let now = chrono::Utc::now().timestamp();
        let mut sources: Vec<SourceEntry> = self
            .sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| sx_answer_source_eligible(e, exclude_ip, now))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        sources.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        sources.truncate(MAX_SOURCES_IN_RESPONSE);

        build_answer_sources1_versioned(&sources, file_hash, requested_version)
    }

    pub fn remove_source(&mut self, file_hash: &[u8; 16], ip: &Ipv4Addr, port: u16) {
        if let Some(entries) = self.sources.get_mut(file_hash) {
            entries.retain(|e| !(e.ip == *ip && e.tcp_port == port));
        }
    }

    pub fn cleanup_expired(&mut self) {
        let now = chrono::Utc::now().timestamp();
        for entries in self.sources.values_mut() {
            entries.retain(|e| now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS);
        }
        self.sources.retain(|_, v| !v.is_empty());
    }

    /// Number of **currently-known** sources for a file: entries whose
    /// `last_seen` is within `SOURCE_EXPIRY_SECS`. Expired entries are
    /// deliberately retained in the map (they still serve user-hash /
    /// connect-option lookups so we can obfuscate to crypt-required peers
    /// immediately after a restart — `save_to_disk` keeps them for 6×expiry),
    /// but they must NOT be counted as live sources. Counting raw `len()` made
    /// the UI's "known sources" figure climb every session — stale entries
    /// reloaded from `sources.met` accumulated on top of the live swarm and
    /// the per-download total latched monotonically — so the number grew on
    /// each close/reopen. Filtering by expiry here keeps the count honest and
    /// also stops discovery gates (`MAX_SOURCES_FOR_UDP`) from tripping on
    /// stale entries.
    pub fn source_count(&self, file_hash: &[u8; 16]) -> usize {
        let now = chrono::Utc::now().timestamp();
        self.sources
            .get(file_hash)
            .map(|v| {
                // eMule keys a client by user hash (CUpDownClient::Compare):
                // two SourceEntries with the same hash are ONE source, not two
                // — e.g. a peer tracked at both its advertised listening port
                // and the ephemeral outbound port of an adopted callback/
                // push-grant connection. Count each distinct non-zero identity
                // once, plus each hash-less entry once. Only non-expired
                // entries count (stale entries linger for hash/crypt lookups).
                let mut seen: std::collections::HashSet<[u8; 16]> =
                    std::collections::HashSet::new();
                let mut count = 0usize;
                for e in v
                    .iter()
                    .filter(|e| now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS)
                {
                    if e.user_hash == [0u8; 16] || seen.insert(e.user_hash) {
                        count += 1;
                    }
                }
                count
            })
            .unwrap_or(0)
    }

    /// Return non-expired sources that have UDP ports (without reask gating).
    pub fn get_udp_sources(&self, file_hash: &[u8; 16]) -> Vec<(Ipv4Addr, u16, u16)> {
        let now = chrono::Utc::now().timestamp();
        self.sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| {
                        now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS && e.udp_port > 0
                    })
                    .map(|e| (e.ip, e.tcp_port, e.udp_port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return UDP sources due for a re-ask (eMule: SOURCECLIENTREASKS interval).
    /// Only returns sources whose `last_asked` is older than `reask_interval` seconds ago.
    pub fn get_udp_sources_due_for_reask(
        &self,
        file_hash: &[u8; 16],
        reask_interval: i64,
    ) -> Vec<(Ipv4Addr, u16, u16)> {
        let now = chrono::Utc::now().timestamp();
        self.sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| {
                        now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS
                            && e.udp_port > 0
                            && (now - e.last_asked) >= reask_interval
                    })
                    .map(|e| (e.ip, e.tcp_port, e.udp_port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Mark a source as asked (update `last_asked` timestamp).
    pub fn mark_asked(&mut self, file_hash: &[u8; 16], ip: Ipv4Addr, port: u16) {
        let now = chrono::Utc::now().timestamp();
        if let Some(entries) = self.sources.get_mut(file_hash) {
            if let Some(entry) = entries
                .iter_mut()
                .find(|e| e.ip == ip && e.tcp_port == port)
            {
                entry.last_asked = now;
            }
        }
    }

    /// Check if enough time has passed since the last SX request to this source
    /// (eMule SOURCECLIENTREASKS = 40 min).
    pub fn can_request_sources_for(&self, file_hash: &[u8; 16], ip: Ipv4Addr, port: u16) -> bool {
        let now = chrono::Utc::now().timestamp();
        if let Some(entries) = self.sources.get(file_hash) {
            if let Some(entry) = entries.iter().find(|e| e.ip == ip && e.tcp_port == port) {
                return entry.last_sx_sent == 0
                    || (now - entry.last_sx_sent) >= SOURCECLIENTREASKS_I64;
            }
        }
        true
    }

    /// Record that an SX request was sent to this source.
    pub fn mark_sx_sent(&mut self, file_hash: &[u8; 16], ip: Ipv4Addr, port: u16) {
        let now = chrono::Utc::now().timestamp();
        if let Some(entries) = self.sources.get_mut(file_hash) {
            if let Some(entry) = entries
                .iter_mut()
                .find(|e| e.ip == ip && e.tcp_port == port)
            {
                entry.last_sx_sent = now;
            }
        }
    }

    /// Return non-expired HighID sources for a file (directly connectable).
    pub fn get_sources(&self, file_hash: &[u8; 16]) -> Vec<(Ipv4Addr, u16)> {
        let now = chrono::Utc::now().timestamp();
        self.sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| {
                        now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS
                            && e.client_id == 0
                            && !e.ip.is_unspecified()
                    })
                    .map(|e| (e.ip, e.tcp_port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Look up a stored user hash for a specific source by IP:port.
    pub fn get_user_hash(&self, file_hash: &[u8; 16], ip: Ipv4Addr, port: u16) -> Option<[u8; 16]> {
        self.sources.get(file_hash).and_then(|entries| {
            entries
                .iter()
                .find(|e| e.ip == ip && e.tcp_port == port && e.user_hash != [0u8; 16])
                .map(|e| e.user_hash)
        })
    }

    pub fn get_connect_options(&self, file_hash: &[u8; 16], ip: Ipv4Addr, port: u16) -> Option<u8> {
        self.sources.get(file_hash).and_then(|entries| {
            entries
                .iter()
                .find(|e| e.ip == ip && e.tcp_port == port)
                .map(|e| e.connect_options)
        })
    }

    /// Look up a stored user hash for a peer by IP:port across ALL tracked
    /// files. eMule keys client identity globally (`clientlist`), so a hash
    /// learned for one file (via the KAD answer-ID, source exchange, or a prior
    /// handshake) can enable TCP obfuscation for the same peer on a different
    /// file — even when the eD2K server omitted the 0x80 user hash for that
    /// source. Without this, crypt-required server HighID sources stay
    /// plaintext and get reset (`os error 10054`).
    pub fn get_user_hash_by_addr(&self, ip: Ipv4Addr, port: u16) -> Option<[u8; 16]> {
        for entries in self.sources.values() {
            if let Some(e) = entries
                .iter()
                .find(|e| e.ip == ip && e.tcp_port == port && e.user_hash != [0u8; 16])
            {
                return Some(e.user_hash);
            }
        }
        None
    }

    /// Look up stored connect/crypt options for a peer by IP:port across ALL
    /// tracked files (see [`get_user_hash_by_addr`]).
    pub fn get_connect_options_by_addr(&self, ip: Ipv4Addr, port: u16) -> Option<u8> {
        for entries in self.sources.values() {
            if let Some(e) = entries
                .iter()
                .find(|e| e.ip == ip && e.tcp_port == port && e.connect_options != 0)
            {
                return Some(e.connect_options);
            }
        }
        None
    }

    /// Persist the source cache to disk (eMule keeps source identities in its
    /// `clientlist`/part.met so it can obfuscate connections to crypt-required
    /// peers immediately after a restart instead of getting reset until it
    /// re-learns each hash). We only persist sources that carry a user hash —
    /// those are the ones that unlock obfuscation — newest first, capped per
    /// file. Returns the number of sources written.
    ///
    /// Wire format (`sources.met`): `b"ESRC"` magic, version `1`, then
    /// `u32` file count, and per file a 16-byte hash, `u16` source count and a
    /// fixed 43-byte record per source (4 ip + 2 tcp + 2 udp + 4 server ip +
    /// 2 server port + 16 user hash + 1 options + 4 client id + 8 last_seen).
    pub fn save_to_disk(&self, path: &std::path::Path) -> std::io::Result<usize> {
        const PERSIST_PER_FILE: usize = 200;
        let now = chrono::Utc::now().timestamp();
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"ESRC");
        buf.push(1u8);

        let mut file_records: Vec<(&[u8; 16], Vec<&SourceEntry>)> = Vec::new();
        for (fh, entries) in &self.sources {
            let mut keep: Vec<&SourceEntry> = entries
                .iter()
                .filter(|e| {
                    e.user_hash != [0u8; 16]
                        && now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS * 6
                })
                .collect();
            if keep.is_empty() {
                continue;
            }
            keep.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
            keep.truncate(PERSIST_PER_FILE);
            file_records.push((fh, keep));
        }

        buf.extend_from_slice(&(file_records.len() as u32).to_le_bytes());
        let mut total = 0usize;
        for (fh, entries) in &file_records {
            buf.extend_from_slice(*fh);
            buf.extend_from_slice(&(entries.len() as u16).to_le_bytes());
            for e in entries {
                buf.extend_from_slice(&e.ip.octets());
                buf.extend_from_slice(&e.tcp_port.to_le_bytes());
                buf.extend_from_slice(&e.udp_port.to_le_bytes());
                buf.extend_from_slice(&e.server_ip.to_le_bytes());
                buf.extend_from_slice(&e.server_port.to_le_bytes());
                buf.extend_from_slice(&e.user_hash);
                buf.push(e.connect_options);
                buf.extend_from_slice(&e.client_id.to_le_bytes());
                buf.extend_from_slice(&e.last_seen.to_le_bytes());
                total += 1;
            }
        }

        let tmp = path.with_extension("met.tmp");
        std::fs::write(&tmp, &buf)?;
        std::fs::rename(&tmp, path)?;
        Ok(total)
    }

    /// Load the source cache written by [`save_to_disk`], merging the entries
    /// into the in-memory map. Entries already present (same file + IP:port)
    /// are not overwritten; only their hash/options are filled in if missing.
    /// Returns the number of sources loaded.
    pub fn load_from_disk(&mut self, path: &std::path::Path) -> std::io::Result<usize> {
        let data = std::fs::read(path)?;
        if data.len() < 9 || &data[0..4] != b"ESRC" || data[4] != 1 {
            return Ok(0);
        }
        let mut pos = 5usize;
        let read_u16 = |d: &[u8], p: usize| u16::from_le_bytes([d[p], d[p + 1]]);
        let read_u32 =
            |d: &[u8], p: usize| u32::from_le_bytes([d[p], d[p + 1], d[p + 2], d[p + 3]]);
        let read_i64 = |d: &[u8], p: usize| {
            i64::from_le_bytes([
                d[p],
                d[p + 1],
                d[p + 2],
                d[p + 3],
                d[p + 4],
                d[p + 5],
                d[p + 6],
                d[p + 7],
            ])
        };

        if pos + 4 > data.len() {
            return Ok(0);
        }
        let file_count = read_u32(&data, pos);
        pos += 4;
        let mut loaded = 0usize;
        for _ in 0..file_count {
            if pos + 18 > data.len() {
                break;
            }
            let mut fh = [0u8; 16];
            fh.copy_from_slice(&data[pos..pos + 16]);
            pos += 16;
            let src_count = read_u16(&data, pos);
            pos += 2;
            let entries = self.sources.entry(fh).or_default();
            for _ in 0..src_count {
                // record = 4+2+2+4+2+16+1+4+8 = 43 bytes
                if pos + 43 > data.len() {
                    pos = data.len();
                    break;
                }
                let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
                let tcp_port = read_u16(&data, pos + 4);
                let udp_port = read_u16(&data, pos + 6);
                let server_ip = read_u32(&data, pos + 8);
                let server_port = read_u16(&data, pos + 12);
                let mut user_hash = [0u8; 16];
                user_hash.copy_from_slice(&data[pos + 14..pos + 30]);
                let connect_options = data[pos + 30];
                let client_id = read_u32(&data, pos + 31);
                let last_seen = read_i64(&data, pos + 35);
                pos += 43;

                if let Some(existing) = entries
                    .iter_mut()
                    .find(|e| e.ip == ip && e.tcp_port == tcp_port)
                {
                    if existing.user_hash == [0u8; 16] && user_hash != [0u8; 16] {
                        existing.user_hash = user_hash;
                    }
                    if existing.connect_options == 0 {
                        existing.connect_options = connect_options;
                    }
                    continue;
                }
                if entries.len() >= self.max_per_file {
                    continue;
                }
                entries.push(SourceEntry {
                    ip,
                    tcp_port,
                    udp_port,
                    server_ip,
                    server_port,
                    last_seen,
                    user_hash,
                    connect_options,
                    client_id,
                    last_asked: 0,
                    last_sx_sent: 0,
                    last_callback_at: 0,
                });
                loaded += 1;
            }
        }
        Ok(loaded)
    }

    /// Register a LowID source (behind NAT, needs server callback to reach).
    pub fn register_lowid_source(
        &mut self,
        file_hash: [u8; 16],
        client_id: u32,
        port: u16,
        server_ip: u32,
        server_port: u16,
        user_hash: [u8; 16],
        connect_options: u8,
    ) {
        let now = chrono::Utc::now().timestamp();
        let entries = self.sources.entry(file_hash).or_default();

        // A LowID `client_id` is only unique *within one server* — different
        // servers routinely hand out the same low IDs to different peers. Key
        // the dedup on `(client_id, server)` so a same-numbered LowID source
        // learned from another server can't silently overwrite (and thereby
        // lose the reachability of) an already-tracked peer.
        if let Some(existing) = entries.iter_mut().find(|e| {
            e.client_id == client_id
                && client_id > 0
                && e.server_ip == server_ip
                && e.server_port == server_port
        }) {
            existing.last_seen = now;
            existing.tcp_port = port;
            existing.server_ip = server_ip;
            existing.server_port = server_port;
            if user_hash != [0u8; 16] {
                existing.user_hash = user_hash;
            }
            if connect_options != 0 {
                existing.connect_options = connect_options;
            }
            return;
        }

        if entries.len() >= self.max_per_file {
            entries.sort_by_key(|e| e.last_seen);
            entries.remove(0);
        }

        entries.push(SourceEntry {
            ip: Ipv4Addr::UNSPECIFIED,
            tcp_port: port,
            udp_port: 0,
            server_ip,
            server_port,
            last_seen: now,
            user_hash,
            connect_options,
            client_id,
            last_asked: 0,
            last_sx_sent: 0,
            last_callback_at: 0,
        });
    }

    /// Return non-expired LowID sources that need server callbacks.
    #[allow(dead_code)]
    pub fn get_lowid_sources(&self, file_hash: &[u8; 16]) -> Vec<(u32, u16, u32, u16)> {
        let now = chrono::Utc::now().timestamp();
        self.sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| {
                        now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS && e.client_id > 0
                    })
                    .map(|e| (e.client_id, e.tcp_port, e.server_ip, e.server_port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return non-expired LowID sources that haven't had a callback requested
    /// within `min_interval_secs` (eMule: FILEREASKTIME ≈ 29 min).
    /// Only returns sources on the specified server.
    pub fn get_lowid_sources_needing_callback(
        &self,
        file_hash: &[u8; 16],
        server_ip: u32,
        server_port: u16,
        min_interval_secs: i64,
    ) -> Vec<u32> {
        let now = chrono::Utc::now().timestamp();
        self.sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| {
                        e.client_id > 0
                            && now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS
                            && e.server_ip == server_ip
                            && e.server_port == server_port
                            && (e.last_callback_at == 0
                                || now.saturating_sub(e.last_callback_at) >= min_interval_secs)
                    })
                    .map(|e| e.client_id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// L-2 helper: return every (file_hash, client_id) pair eligible
    /// for a callback request through `(server_ip, server_port)` —
    /// across **all** files we know sources for. Called when we
    /// successfully (re)connect TCP to a server, so we can request
    /// callbacks for LowID sources that were learned earlier via UDP
    /// from that same server but couldn't be reached because we
    /// weren't TCP-connected to it at the time.
    ///
    /// Without this, UDP-discovered LowID sources from a non-current
    /// server were stored but never reachable — the original audit
    /// flagged this as an effectively-dead source population.
    pub fn get_lowid_sources_for_server(
        &self,
        server_ip: u32,
        server_port: u16,
        min_interval_secs: i64,
    ) -> Vec<([u8; 16], u32)> {
        let now = chrono::Utc::now().timestamp();
        let mut out = Vec::new();
        for (file_hash, entries) in &self.sources {
            for e in entries {
                if e.client_id == 0 {
                    continue;
                }
                if e.server_ip != server_ip || e.server_port != server_port {
                    continue;
                }
                if now.saturating_sub(e.last_seen) >= SOURCE_EXPIRY_SECS {
                    continue;
                }
                if e.last_callback_at != 0
                    && now.saturating_sub(e.last_callback_at) < min_interval_secs
                {
                    continue;
                }
                out.push((*file_hash, e.client_id));
            }
        }
        out
    }

    /// D11: return LowID sources for a file that are eligible for a
    /// callback, grouped by the server they were announced through. Lets
    /// the caller switch eMule servers on the fly (or talk to multiple
    /// servers) without losing track of a LowID source that was only ever
    /// seen through a different server.
    ///
    /// Returns `Vec<(server_ip, server_port, Vec<client_id>)>`.
    #[allow(dead_code)]
    pub fn get_lowid_sources_by_server(
        &self,
        file_hash: &[u8; 16],
        min_interval_secs: i64,
    ) -> Vec<(u32, u16, Vec<u32>)> {
        let now = chrono::Utc::now().timestamp();
        let entries = match self.sources.get(file_hash) {
            Some(e) => e,
            None => return Vec::new(),
        };
        let mut grouped: std::collections::HashMap<(u32, u16), Vec<u32>> =
            std::collections::HashMap::new();
        for e in entries {
            if e.client_id == 0 {
                continue;
            }
            if now.saturating_sub(e.last_seen) >= SOURCE_EXPIRY_SECS {
                continue;
            }
            if e.server_ip == 0 || e.server_port == 0 {
                continue;
            }
            if e.last_callback_at != 0 && now.saturating_sub(e.last_callback_at) < min_interval_secs
            {
                continue;
            }
            grouped
                .entry((e.server_ip, e.server_port))
                .or_default()
                .push(e.client_id);
        }
        grouped
            .into_iter()
            .map(|((ip, port), ids)| (ip, port, ids))
            .collect()
    }

    /// Record that OP_CALLBACKREQUEST was sent for a LowID source. Now that
    /// `register_lowid_source` keeps one row per `(client_id, server)`, a file
    /// can legitimately hold several rows sharing a `client_id` (the same low ID
    /// handed out by different servers). We only hold a TCP link to one server
    /// at a time and request callbacks through it, but throttling *every* row
    /// with this `client_id` is the safe choice: it stops the per-cycle re-ask
    /// loop from re-sending immediately, and the rare over-throttle of a
    /// different server's identically-numbered row merely defers its callback by
    /// one `FILEREASKTIME` window — far better than a callback-spam loop.
    pub fn mark_callback_sent(&mut self, file_hash: &[u8; 16], client_id: u32) {
        let now = chrono::Utc::now().timestamp();
        if let Some(entries) = self.sources.get_mut(file_hash) {
            for entry in entries.iter_mut().filter(|e| e.client_id == client_id) {
                entry.last_callback_at = now;
            }
        }
    }

    /// Link a just-connected server-LowID callback to the LowID source row we
    /// already track for it, stamping the peer's now-known user hash so the
    /// swarm isn't double-counted.
    ///
    /// A LowID source is learned from a server source list as
    /// `(client_id, listening_port, server)` with an unknown user hash and no
    /// routable IP. When the peer answers our `OP_CALLBACKREQUEST` it connects
    /// from an *ephemeral* port, and that live connection is separately
    /// registered as an ordinary `(real_ip, ephemeral_port, hash)` row. Without
    /// linking the two, `source_count` (which de-dupes by user hash) counts the
    /// peer twice — once as the hash-less LowID row, once as the hashed live row.
    ///
    /// We match by `(server, listening_port)` because the peer's Hello carries
    /// its *listening* port, not the ephemeral source port of this connection.
    /// We only stamp the hash + refresh `last_seen`; the row stays LowID (its
    /// `client_id` and unspecified IP are untouched) so reconnects still go via
    /// a fresh server callback — a LowID peer is never directly dialable.
    ///
    /// Disambiguation is deliberately conservative: if a row already carries
    /// this exact hash we just refresh it, otherwise we stamp only when there is
    /// *exactly one* hash-less candidate. Two hash-less LowID peers from the
    /// same server that both advertise the same listening port (e.g. the 4662
    /// default) are indistinguishable here, so we leave them alone rather than
    /// risk pinning the wrong identity onto a peer. `listening_port == 0` or a
    /// zero `user_hash` matches nothing.
    pub fn link_lowid_callback_identity(
        &mut self,
        server_ip: u32,
        server_port: u16,
        listening_port: u16,
        user_hash: [u8; 16],
    ) {
        if listening_port == 0 || user_hash == [0u8; 16] {
            return;
        }
        let now = chrono::Utc::now().timestamp();
        for entries in self.sources.values_mut() {
            let mut exact_idx: Option<usize> = None;
            let mut hashless_idx: Option<usize> = None;
            let mut hashless_count = 0usize;
            for (i, e) in entries.iter().enumerate() {
                if e.client_id > 0
                    && e.tcp_port == listening_port
                    && e.server_ip == server_ip
                    && e.server_port == server_port
                {
                    if e.user_hash == user_hash {
                        exact_idx = Some(i);
                        break;
                    } else if e.user_hash == [0u8; 16] {
                        hashless_count += 1;
                        hashless_idx = Some(i);
                    }
                }
            }
            if let Some(i) = exact_idx {
                entries[i].last_seen = now;
            } else if hashless_count == 1 {
                if let Some(i) = hashless_idx {
                    entries[i].user_hash = user_hash;
                    entries[i].last_seen = now;
                }
            }
        }
    }

    pub fn find_lowid_files_by_port(
        &self,
        server_ip: u32,
        server_port: u16,
        tcp_port: u16,
        user_hash: Option<[u8; 16]>,
    ) -> Vec<[u8; 16]> {
        let now = chrono::Utc::now().timestamp();
        let candidates: Vec<[u8; 16]> = self
            .sources
            .iter()
            .filter_map(|(file_hash, entries)| {
                entries
                    .iter()
                    .any(|e| {
                        now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS
                            && e.client_id > 0
                            && e.tcp_port == tcp_port
                            && e.server_ip == server_ip
                            && e.server_port == server_port
                    })
                    .then_some(*file_hash)
            })
            .collect();

        if let Some(hash) = user_hash.filter(|h| *h != [0u8; 16]) {
            let filtered: Vec<[u8; 16]> = self
                .sources
                .iter()
                .filter_map(|(file_hash, entries)| {
                    entries
                        .iter()
                        .any(|e| {
                            now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS
                                && e.client_id > 0
                                && e.tcp_port == tcp_port
                                && e.server_ip == server_ip
                                && e.server_port == server_port
                                && e.user_hash == hash
                        })
                        .then_some(*file_hash)
                })
                .collect();
            if !filtered.is_empty() {
                return filtered;
            }
        }

        if candidates.len() == 1 {
            candidates
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn failure_score_decays_after_queue_progress() {
        let hash = [0x11; 16];
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let mut pfs = PerFileSourceList::new(hash);
        assert!(pfs.add_source_full(ip, 4662, 4672));

        pfs.set_failed_with_penalty(ip, 4662, 4);
        assert_eq!(pfs.sources[0].fail_count, 4);

        pfs.set_on_queue(ip, 4662, Some(10));
        assert_eq!(pfs.sources[0].fail_count, 3);

        pfs.set_none_needed_parts(ip, 4662);
        assert_eq!(pfs.sources[0].fail_count, 2);
    }

    #[test]
    fn sources_ready_for_reask_prioritizes_queue_rank() {
        let hash = [0x22; 16];
        let a = Ipv4Addr::new(1, 1, 1, 1);
        let b = Ipv4Addr::new(2, 2, 2, 2);
        let mut pfs = PerFileSourceList::new(hash);
        assert!(pfs.add_source_full(a, 4662, 4672));
        assert!(pfs.add_source_full(b, 4663, 4673));

        pfs.set_on_queue(a, 4662, Some(50));
        pfs.set_on_queue(b, 4663, Some(5));
        let now = Instant::now() + Duration::from_secs(2000);

        let ready = pfs.sources_ready_for_reask_at(now);
        assert_eq!(ready, vec![(b, 4663), (a, 4662)]);
    }

    #[test]
    fn purge_dead_sources_removes_only_heavily_penalized_entries() {
        let hash = [0x33; 16];
        let keep_ip = Ipv4Addr::new(3, 3, 3, 3);
        let drop_ip = Ipv4Addr::new(4, 4, 4, 4);
        let mut pfs = PerFileSourceList::new(hash);
        assert!(pfs.add_source_full(keep_ip, 4662, 0));
        assert!(pfs.add_source_full(drop_ip, 4663, 0));

        pfs.set_failed_with_penalty(keep_ip, 4662, 3);
        pfs.set_failed_with_penalty(drop_ip, 4663, 9);
        pfs.purge_dead_sources();

        assert_eq!(pfs.sources.len(), 1);
        assert_eq!(pfs.sources[0].ip, keep_ip);
    }

    #[test]
    fn source_count_excludes_expired_but_keeps_them_stored() {
        // Regression: the per-download "known sources" figure climbed on every
        // close/reopen because `source_count` returned the raw vec length,
        // counting stale entries that `sources.met` retains (6×expiry) for
        // crypt/user-hash lookups and reloads on startup. The count must
        // reflect only live (non-expired) sources, while expired entries stay
        // in the map for their hash-lookup purpose.
        let hash = [0x55; 16];
        let mut sm = SourceManager::new();
        let live = Ipv4Addr::new(7, 7, 7, 7);
        let stale = Ipv4Addr::new(8, 8, 8, 8);
        sm.register_source(hash, live, 4662);
        sm.register_source(hash, stale, 4663);
        assert_eq!(sm.source_count(&hash), 2);

        let now = chrono::Utc::now().timestamp();
        for e in sm.sources.get_mut(&hash).unwrap().iter_mut() {
            if e.ip == stale {
                e.last_seen = now - (SOURCE_EXPIRY_SECS + 60);
            }
        }

        assert_eq!(
            sm.source_count(&hash),
            1,
            "expired source must not be counted"
        );
        assert_eq!(
            sm.sources.get(&hash).map(|v| v.len()),
            Some(2),
            "expired source must remain stored for crypt/user-hash lookups"
        );
    }

    #[test]
    fn kad_callback_reask_is_immediate_for_new_sources() {
        let hash = [0x44; 16];
        let ip = Ipv4Addr::new(5, 5, 5, 5);
        let buddy = Ipv4Addr::new(6, 6, 6, 6);
        let mut pfs = PerFileSourceList::new(hash);
        assert!(pfs.add_source_full(ip, 4662, 0));
        pfs.set_kad_callback_buddy(ip, 4662, buddy, 4672, [0xAA; 16], Some([0xBB; 16]), true);
        assert!(pfs.callback_reask_due(ip, 4662));
        pfs.mark_callback_requested(ip, 4662);
        assert!(!pfs.callback_reask_due(ip, 4662));
    }

    #[test]
    fn link_lowid_callback_stamps_single_row_and_dedups_count() {
        // A LowID source learned from a server (hash unknown) plus the live
        // callback connection (registered at its ephemeral port with the peer's
        // hash) must collapse to ONE counted source once we link them by the
        // peer's advertised listening port.
        let hash = [0x91; 16];
        let srv_ip = u32::from_le_bytes([1, 2, 3, 4]);
        let srv_port = 4661u16;
        let peer_hash = [0xC7; 16];
        let real_ip = Ipv4Addr::new(9, 9, 9, 9);
        let listening_port = 4662u16;
        let ephemeral_port = 51000u16;

        let mut sm = SourceManager::new();
        // LowID row from the server source list: client_id set, hash unknown.
        sm.register_lowid_source(hash, 5, listening_port, srv_ip, srv_port, [0u8; 16], 0);
        // Live callback connection lands on the ephemeral port, hash known.
        sm.register_source_full_opts(hash, real_ip, ephemeral_port, 0, peer_hash, 0);
        assert_eq!(sm.source_count(&hash), 2, "before linking: counted twice");

        sm.link_lowid_callback_identity(srv_ip, srv_port, listening_port, peer_hash);

        assert_eq!(
            sm.source_count(&hash),
            1,
            "after linking the LowID row carries the peer hash, so it de-dupes"
        );
        // The row stays LowID (client_id kept, IP still unspecified) so future
        // reconnects still go through a fresh server callback.
        let lowid_row = sm
            .sources
            .get(&hash)
            .unwrap()
            .iter()
            .find(|e| e.client_id == 5)
            .expect("LowID row still present");
        assert_eq!(
            lowid_row.user_hash, peer_hash,
            "hash stamped onto LowID row"
        );
        assert_eq!(
            lowid_row.ip,
            Ipv4Addr::UNSPECIFIED,
            "row stays LowID (no routable IP)"
        );
    }

    #[test]
    fn link_lowid_callback_skips_ambiguous_colisteners() {
        // Two different LowID peers from the same server both advertising the
        // default listening port are indistinguishable at callback time, so a
        // single callback must NOT pin its identity onto either of them.
        let hash = [0x92; 16];
        let srv_ip = u32::from_le_bytes([1, 2, 3, 4]);
        let srv_port = 4661u16;
        let peer_hash = [0xD3; 16];
        let listening_port = 4662u16;

        let mut sm = SourceManager::new();
        sm.register_lowid_source(hash, 5, listening_port, srv_ip, srv_port, [0u8; 16], 0);
        sm.register_lowid_source(hash, 7, listening_port, srv_ip, srv_port, [0u8; 16], 0);

        sm.link_lowid_callback_identity(srv_ip, srv_port, listening_port, peer_hash);

        for e in sm.sources.get(&hash).unwrap() {
            assert_eq!(
                e.user_hash, [0u8; 16],
                "ambiguous co-listeners must be left unstamped"
            );
        }
    }

    #[test]
    fn link_lowid_callback_refreshes_exact_hash_row_only() {
        // When a row already carries this exact identity (a reconnect), we only
        // refresh it — and we must not stamp a *different* co-listening peer.
        let hash = [0x93; 16];
        let srv_ip = u32::from_le_bytes([5, 6, 7, 8]);
        let srv_port = 4665u16;
        let known_hash = [0x1A; 16];
        let other_hash = [0u8; 16];
        let listening_port = 5000u16;

        let mut sm = SourceManager::new();
        // Known peer (already linked earlier) and a different hash-less peer,
        // both LowID on the same server but *different* listening ports so the
        // known one is matched unambiguously.
        sm.register_lowid_source(hash, 5, listening_port, srv_ip, srv_port, known_hash, 0);
        sm.register_lowid_source(hash, 7, 5001, srv_ip, srv_port, other_hash, 0);
        // Age the known row so we can observe the refresh.
        let stale = chrono::Utc::now().timestamp() - 100;
        for e in sm.sources.get_mut(&hash).unwrap().iter_mut() {
            e.last_seen = stale;
        }

        sm.link_lowid_callback_identity(srv_ip, srv_port, listening_port, known_hash);

        let rows = sm.sources.get(&hash).unwrap();
        let known = rows.iter().find(|e| e.client_id == 5).unwrap();
        let other = rows.iter().find(|e| e.client_id == 7).unwrap();
        assert!(known.last_seen > stale, "exact-hash row refreshed");
        assert_eq!(other.last_seen, stale, "unrelated row untouched");
        assert_eq!(other.user_hash, [0u8; 16], "unrelated row not stamped");
    }
}
