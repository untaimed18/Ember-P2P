use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use super::dead_sources::{FILEREASKTIME_SECS, SOURCECLIENTREASKS_SECS as SOURCECLIENTREASKS_I64};
use super::messages::build_answer_sources1_versioned;
use super::transfer::is_filtered_source_ip;

const MAX_SOURCES_PER_FILE: usize = 500;
const SOURCE_EXPIRY_SECS: i64 = 3600;
const MAX_SOURCES_IN_RESPONSE: usize = 500;
const MAX_TRACKED_FILES: usize = 500;

/// eMule: minimum gap between TCP connection attempts to the same source (20 min)
const MIN_TCP_RECONNECT_SECS: i64 = 1200;


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
    /// When the state last changed (for timeout decisions).
    pub state_changed: Instant,
    /// Number of consecutive failures without a successful data transfer.
    pub fail_count: u32,
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
            state_changed: now,
            fail_count: 0,
        }
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
        let interval = match &self.state {
            DownloadSourceState::New => return 0,
            DownloadSourceState::NoneNeededParts => (FILEREASKTIME_SECS * 2) as u64,
            DownloadSourceState::Failed | DownloadSourceState::TooManyConns => FILEREASKTIME_SECS as u64,
            DownloadSourceState::OnQueue { .. } => FILEREASKTIME_SECS as u64,
            DownloadSourceState::WaitCallback | DownloadSourceState::WaitCallbackKad => FILEREASKTIME_SECS as u64,
            DownloadSourceState::Connecting | DownloadSourceState::Downloading => {
                // Watchdog: if a source has been `Connecting` /
                // `Downloading` far longer than any legitimate handshake
                // or transfer gap, treat it as stuck and allow a fresh
                // reask. Without this, a panicked or killed driver task
                // leaves the source permanently "active" and the
                // scheduler can't pick it up again until the next full
                // list reset.
                if self.state_changed.elapsed().as_secs() >= Self::CONNECTING_WATCHDOG_SECS {
                    return 0;
                }
                return u64::MAX;
            }
            DownloadSourceState::LowToLowIp | DownloadSourceState::EmberRelay | DownloadSourceState::Banned => return u64::MAX,
        };
        let elapsed = self.last_asked.elapsed().as_secs();
        interval.saturating_sub(elapsed)
    }

    /// Whether enough time has passed since the last TCP attempt.
    pub fn can_try_tcp(&self) -> bool {
        self.last_asked.elapsed().as_secs() >= MIN_TCP_RECONNECT_SECS as u64
            || matches!(self.state, DownloadSourceState::New)
    }

    /// Whether this source should receive a UDP reask ping
    /// (27 min after last ask, i.e. 2 min before FILEREASKTIME).
    pub fn needs_udp_reask(&self) -> bool {
        if self.udp_port == 0 { return false; }
        let elapsed = self.last_asked.elapsed().as_secs();
        let threshold = (FILEREASKTIME_SECS - 120).max(0) as u64;
        matches!(self.state, DownloadSourceState::OnQueue { .. } | DownloadSourceState::Failed)
            && elapsed >= threshold
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
        self.sources.iter().any(|s| s.ip == ip && s.tcp_port == tcp_port)
    }

    pub fn add_source_full(&mut self, ip: Ipv4Addr, tcp_port: u16, udp_port: u16) -> bool {
        if self.sources.len() >= MAX_SOURCES_PER_FILE {
            return false;
        }
        if let Some(existing) = self.sources.iter_mut().find(|s| s.ip == ip && s.tcp_port == tcp_port) {
            if udp_port > 0 {
                existing.udp_port = udp_port;
            }
            return false;
        }
        let mut entry = DownloadSourceEntry::new(ip, tcp_port);
        entry.udp_port = udp_port;
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
    pub fn sources_ready_for_reask(&self) -> Vec<(Ipv4Addr, u16)> {
        let mut ready: Vec<&DownloadSourceEntry> = self.sources.iter()
            .filter(|s| {
                s.time_until_reask() == 0
                    && s.can_try_tcp()
                    && !matches!(s.state, DownloadSourceState::Banned | DownloadSourceState::LowToLowIp | DownloadSourceState::EmberRelay)
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
            rank_a.cmp(&rank_b).then_with(|| a.fail_count.cmp(&b.fail_count))
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
        let mut ready: Vec<&DownloadSourceEntry> = self.sources.iter()
            .filter(|s| {
                s.time_until_reask() == 0
                    && s.can_try_tcp()
                    && !matches!(s.state, DownloadSourceState::Banned | DownloadSourceState::LowToLowIp | DownloadSourceState::EmberRelay)
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
            rank_a.cmp(&rank_b)
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
        self.sources.iter()
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
            s.last_asked = std::time::Instant::now();
        }
    }

    /// Count sources in OnQueue or Downloading state (eMule: m_nCompleteSourcesCount).
    pub fn complete_source_count(&self) -> u16 {
        self.sources.iter()
            .filter(|s| matches!(s.state, DownloadSourceState::OnQueue { .. } | DownloadSourceState::Downloading))
            .count()
            .min(u16::MAX as usize) as u16
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
            if matches!(s.state, DownloadSourceState::Connecting | DownloadSourceState::Downloading) {
                s.state = DownloadSourceState::Failed;
                s.state_changed = std::time::Instant::now();
            }
        }
    }

    fn find_mut(&mut self, ip: Ipv4Addr, port: u16) -> Option<&mut DownloadSourceEntry> {
        self.sources.iter_mut().find(|s| s.ip == ip && s.tcp_port == port)
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
    fn default() -> Self { Self::new() }
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

    pub fn register_source_with_hash(&mut self, file_hash: [u8; 16], ip: Ipv4Addr, tcp_port: u16, user_hash: [u8; 16]) {
        self.register_source_full(file_hash, ip, tcp_port, 0, user_hash);
    }

    pub fn register_source_full(&mut self, file_hash: [u8; 16], ip: Ipv4Addr, tcp_port: u16, udp_port: u16, user_hash: [u8; 16]) {
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
        self.register_source_full_server(file_hash, ip, tcp_port, udp_port, 0, 0, user_hash, connect_options);
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

        if let Some(existing) = entries.iter_mut().find(|e| e.ip == ip && e.tcp_port == tcp_port) {
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
                    .filter(|e| {
                        e.ip != exclude_ip
                            && e.client_id == 0
                            && !is_filtered_source_ip(&e.ip)
                            && now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS
                    })
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
            if version >= 3 {
                resp.extend_from_slice(&u32::from(src.ip).to_le_bytes());
            } else {
                resp.extend_from_slice(&src.ip.octets());
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
                    .filter(|e| {
                        e.ip != exclude_ip
                            && e.client_id == 0
                            && !is_filtered_source_ip(&e.ip)
                            && now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS
                    })
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

    pub fn source_count(&self, file_hash: &[u8; 16]) -> usize {
        self.sources.get(file_hash).map(|v| v.len()).unwrap_or(0)
    }

    /// Return non-expired sources that have UDP ports (without reask gating).
    pub fn get_udp_sources(&self, file_hash: &[u8; 16]) -> Vec<(Ipv4Addr, u16, u16)> {
        let now = chrono::Utc::now().timestamp();
        self.sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS && e.udp_port > 0)
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
            if let Some(entry) = entries.iter_mut().find(|e| e.ip == ip && e.tcp_port == port) {
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
                return entry.last_sx_sent == 0 || (now - entry.last_sx_sent) >= SOURCECLIENTREASKS_I64;
            }
        }
        true
    }

    /// Record that an SX request was sent to this source.
    pub fn mark_sx_sent(&mut self, file_hash: &[u8; 16], ip: Ipv4Addr, port: u16) {
        let now = chrono::Utc::now().timestamp();
        if let Some(entries) = self.sources.get_mut(file_hash) {
            if let Some(entry) = entries.iter_mut().find(|e| e.ip == ip && e.tcp_port == port) {
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
                    .filter(|e| now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS && e.client_id == 0 && !e.ip.is_unspecified())
                    .map(|e| (e.ip, e.tcp_port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return the network origin for a source: `Some("ed2k")` if the source
    /// was received from an eD2K server (server_ip set), `None` otherwise.
    pub fn get_source_origin(&self, file_hash: &[u8; 16], ip: Ipv4Addr, port: u16) -> Option<&'static str> {
        self.sources.get(file_hash).and_then(|entries| {
            entries.iter()
                .find(|e| e.ip == ip && e.tcp_port == port)
                .and_then(|e| if e.server_ip != 0 { Some("ed2k") } else { None })
        })
    }

    /// Look up a stored user hash for a specific source by IP:port.
    pub fn get_user_hash(&self, file_hash: &[u8; 16], ip: Ipv4Addr, port: u16) -> Option<[u8; 16]> {
        self.sources.get(file_hash).and_then(|entries| {
            entries.iter()
                .find(|e| e.ip == ip && e.tcp_port == port && e.user_hash != [0u8; 16])
                .map(|e| e.user_hash)
        })
    }

    pub fn get_connect_options(&self, file_hash: &[u8; 16], ip: Ipv4Addr, port: u16) -> Option<u8> {
        self.sources.get(file_hash).and_then(|entries| {
            entries.iter()
                .find(|e| e.ip == ip && e.tcp_port == port)
                .map(|e| e.connect_options)
        })
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

        if let Some(existing) = entries.iter_mut().find(|e| e.client_id == client_id && client_id > 0) {
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
                    .filter(|e| now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS && e.client_id > 0)
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
            if e.client_id == 0 { continue; }
            if now.saturating_sub(e.last_seen) >= SOURCE_EXPIRY_SECS { continue; }
            if e.server_ip == 0 || e.server_port == 0 { continue; }
            if e.last_callback_at != 0
                && now.saturating_sub(e.last_callback_at) < min_interval_secs
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

    /// Record that OP_CALLBACKREQUEST was sent for a LowID source.
    pub fn mark_callback_sent(&mut self, file_hash: &[u8; 16], client_id: u32) {
        let now = chrono::Utc::now().timestamp();
        if let Some(entries) = self.sources.get_mut(file_hash) {
            if let Some(entry) = entries.iter_mut().find(|e| e.client_id == client_id) {
                entry.last_callback_at = now;
            }
        }
    }

    /// Promote a LowID source to a HighID source after a callback connection
    /// reveals the peer's real IP. Returns the file hashes this source was
    /// registered for so callers can inject it into active transfers.
    pub fn promote_lowid_source(
        &mut self,
        server_ip: u32,
        server_port: u16,
        tcp_port: u16,
        peer_ip: Ipv4Addr,
        user_hash: [u8; 16],
    ) -> Vec<[u8; 16]> {
        let now = chrono::Utc::now().timestamp();
        let mut promoted_hashes = Vec::new();
        for (file_hash, entries) in &mut self.sources {
            for entry in entries.iter_mut() {
                if entry.client_id > 0
                    && entry.tcp_port == tcp_port
                    && entry.server_ip == server_ip
                    && entry.server_port == server_port
                    && now.saturating_sub(entry.last_seen) < SOURCE_EXPIRY_SECS
                    && (user_hash == [0u8; 16] || entry.user_hash == [0u8; 16] || entry.user_hash == user_hash)
                {
                    entry.ip = peer_ip;
                    if user_hash != [0u8; 16] {
                        entry.user_hash = user_hash;
                    }
                    promoted_hashes.push(*file_hash);
                }
            }
        }
        promoted_hashes
    }

    pub fn find_lowid_files_by_port(
        &self,
        server_ip: u32,
        server_port: u16,
        tcp_port: u16,
        user_hash: Option<[u8; 16]>,
    ) -> Vec<[u8; 16]> {
        let now = chrono::Utc::now().timestamp();
        let candidates: Vec<[u8; 16]> = self.sources
            .iter()
            .filter_map(|(file_hash, entries)| {
                entries.iter().any(|e| {
                    now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS
                        && e.client_id > 0
                        && e.tcp_port == tcp_port
                        && e.server_ip == server_ip
                        && e.server_port == server_port
                }).then_some(*file_hash)
            })
            .collect();

        if let Some(hash) = user_hash.filter(|h| *h != [0u8; 16]) {
            let filtered: Vec<[u8; 16]> = self.sources
                .iter()
                .filter_map(|(file_hash, entries)| {
                    entries.iter().any(|e| {
                        now.saturating_sub(e.last_seen) < SOURCE_EXPIRY_SECS
                            && e.client_id > 0
                            && e.tcp_port == tcp_port
                            && e.server_ip == server_ip
                            && e.server_port == server_port
                            && e.user_hash == hash
                    }).then_some(*file_hash)
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
        pfs.sources[0].last_asked = pfs.sources[0].last_asked - Duration::from_secs(2000);
        pfs.sources[1].last_asked = pfs.sources[1].last_asked - Duration::from_secs(2000);

        let ready = pfs.sources_ready_for_reask();
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
}
