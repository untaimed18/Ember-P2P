use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Maximum reputation score.
const MAX_REPUTATION: i32 = 1000;

/// Minimum reputation score.
const MIN_REPUTATION: i32 = -1000;

/// Default reputation for unknown peers.
const DEFAULT_REPUTATION: i32 = 0;

/// Score changes for various events.
const SCORE_SUCCESSFUL_CHUNK: i32 = 1;
const SCORE_FAILED_CHUNK: i32 = -5;
const SCORE_CORRUPT_DATA: i32 = -50;
const SCORE_TIMEOUT: i32 = -2;
const SCORE_SUCCESSFUL_HANDSHAKE: i32 = 3;
const SCORE_PROTOCOL_VIOLATION: i32 = -20;
const SCORE_DHT_RESPONSE: i32 = 1;

/// Decay interval: scores decay toward zero once per hour.
const DECAY_INTERVAL: Duration = Duration::from_secs(3600);

/// Decay factor (multiply by this each interval).
const DECAY_FACTOR: f64 = 0.95;

/// Reputation threshold below which a peer is banned.
const BAN_THRESHOLD: i32 = -200;
/// IP correlation is intentionally more conservative than identity bans to
/// avoid penalising unrelated peers behind the same NAT.
const IP_BAN_THRESHOLD: i32 = -400;

/// How long a ban lasts.
const BAN_DURATION: Duration = Duration::from_secs(24 * 3600);

/// Maximum number of tracked peers (evict oldest low-reputation entries).
const MAX_TRACKED_PEERS: usize = 10_000;
const MAX_TRACKED_IPS: usize = 10_000;

/// Represents a tracked event type for reputation scoring.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReputationEvent {
    SuccessfulChunk,
    FailedChunk,
    CorruptData,
    Timeout,
    SuccessfulHandshake,
    ProtocolViolation,
    /// Reserved for scoring a peer's DHT/KAD query responses once that
    /// traffic is wired to report reputation events; `SCORE_DHT_RESPONSE`
    /// already exists for it but nothing constructs this variant yet.
    #[allow(dead_code)]
    DhtResponse,
}

impl ReputationEvent {
    fn score_delta(self) -> i32 {
        match self {
            ReputationEvent::SuccessfulChunk => SCORE_SUCCESSFUL_CHUNK,
            ReputationEvent::FailedChunk => SCORE_FAILED_CHUNK,
            ReputationEvent::CorruptData => SCORE_CORRUPT_DATA,
            ReputationEvent::Timeout => SCORE_TIMEOUT,
            ReputationEvent::SuccessfulHandshake => SCORE_SUCCESSFUL_HANDSHAKE,
            ReputationEvent::ProtocolViolation => SCORE_PROTOCOL_VIOLATION,
            ReputationEvent::DhtResponse => SCORE_DHT_RESPONSE,
        }
    }
}

/// Per-peer reputation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    pub node_id: [u8; 16],
    pub score: i32,
    pub successful_transfers: u64,
    pub failed_transfers: u64,
    pub last_interaction: u64,
    pub first_seen: u64,
    pub banned_until: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputation {
    pub ip: [u8; 4],
    pub score: i32,
    pub last_interaction: u64,
    pub banned_until: Option<u64>,
}

impl IpReputation {
    fn new(ip: [u8; 4], now: u64) -> Self {
        Self {
            ip,
            score: DEFAULT_REPUTATION,
            last_interaction: now,
            banned_until: None,
        }
    }

    fn apply_event(&mut self, event: ReputationEvent, now: u64) {
        self.score = (self.score + event.score_delta()).clamp(MIN_REPUTATION, MAX_REPUTATION);
        self.last_interaction = now;
        if self.score <= IP_BAN_THRESHOLD {
            self.banned_until = Some(now + BAN_DURATION.as_secs());
        }
    }

    fn is_banned(&self, now: u64) -> bool {
        self.banned_until.is_some_and(|until| now < until)
    }

    fn apply_decay(&mut self, intervals: u32) {
        if intervals == 0 || self.score == 0 {
            return;
        }
        let factor = DECAY_FACTOR.powi(intervals.min(10_000) as i32);
        self.score = (self.score as f64 * factor)
            .round()
            .clamp(MIN_REPUTATION as f64, MAX_REPUTATION as f64) as i32;
    }
}

impl PeerReputation {
    fn new(node_id: [u8; 16], now: u64) -> Self {
        Self {
            node_id,
            score: DEFAULT_REPUTATION,
            successful_transfers: 0,
            failed_transfers: 0,
            last_interaction: now,
            first_seen: now,
            banned_until: None,
        }
    }

    pub fn is_banned(&self, now: u64) -> bool {
        self.banned_until.map_or(false, |until| now < until)
    }

    fn apply_event(&mut self, event: ReputationEvent, now: u64) {
        let delta = event.score_delta();
        self.score = (self.score + delta).clamp(MIN_REPUTATION, MAX_REPUTATION);
        self.last_interaction = now;

        match event {
            ReputationEvent::SuccessfulChunk => self.successful_transfers += 1,
            ReputationEvent::FailedChunk | ReputationEvent::CorruptData => {
                self.failed_transfers += 1;
            }
            _ => {}
        }

        if self.score <= BAN_THRESHOLD {
            self.banned_until = Some(now + BAN_DURATION.as_secs());
        }
    }

    fn apply_decay(&mut self, intervals: u32) {
        if intervals == 0 || self.score == 0 {
            return;
        }
        // L5: cap the exponent before casting to i32. `intervals` is a
        // u32 derived from `elapsed / DECAY_INTERVAL` which can in
        // pathological cases (clock skew, persisted-state replay)
        // exceed `i32::MAX`. Casting wraps to a negative exponent and
        // sends `factor` to infinity, then `score * factor` is NaN ⇒
        // 0 after the cast. Saturating to a generous ceiling keeps
        // decay monotonic-toward-zero and bounded — `DECAY_FACTOR`
        // raised to ~10000 is already numerically zero, so any
        // larger exponent lands at the same fixed point regardless.
        let exp = intervals.min(10_000) as i32;
        let factor = DECAY_FACTOR.powi(exp);
        self.score = (self.score as f64 * factor).round() as i32;
        self.score = self.score.clamp(MIN_REPUTATION, MAX_REPUTATION);
    }
}

/// On-disk representation of `ReputationManager`. Wrapping the peer list
/// with `last_decay` (rather than persisting a bare array, as before) lets
/// `load()` know how long the process was offline and apply the decay
/// that would otherwise have happened on the normal hourly tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedReputation {
    last_decay: u64,
    peers: Vec<PeerReputation>,
    #[serde(default)]
    ips: Vec<IpReputation>,
}

/// Manages reputation scores for all known peers.
#[derive(Clone)]
pub struct ReputationManager {
    peers: HashMap<[u8; 16], PeerReputation>,
    ips: HashMap<[u8; 4], IpReputation>,
    last_decay: u64,
}

impl ReputationManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            ips: HashMap::new(),
            last_decay: now_secs(),
        }
    }

    /// Record an event for a peer, creating their entry if needed.
    /// Returns `true` if this event caused the peer to become banned.
    pub fn record_event(&mut self, node_id: &[u8; 16], event: ReputationEvent) -> bool {
        let now = now_secs();
        let entry = self
            .peers
            .entry(*node_id)
            .or_insert_with(|| PeerReputation::new(*node_id, now));
        let was_banned = entry.is_banned(now);
        entry.apply_event(event, now);
        let now_banned = entry.is_banned(now);

        if self.peers.len() > MAX_TRACKED_PEERS {
            self.evict_stale();
        }

        !was_banned && now_banned
    }

    /// Record the same event against both the freely-rotatable node identity
    /// and the observed IPv4 address. The stricter IP threshold means normal
    /// NAT-sharing peers are not banned for a handful of failures, while a
    /// Sybil that rotates keys for every violation still accumulates one
    /// address-level score.
    pub fn record_event_with_ip(
        &mut self,
        node_id: &[u8; 16],
        ip: std::net::Ipv4Addr,
        event: ReputationEvent,
    ) -> (bool, bool) {
        let node_banned = self.record_event(node_id, event);
        let now = now_secs();
        let key = ip.octets();
        let entry = self
            .ips
            .entry(key)
            .or_insert_with(|| IpReputation::new(key, now));
        let was_banned = entry.is_banned(now);
        entry.apply_event(event, now);
        let ip_banned = !was_banned && entry.is_banned(now);
        if self.ips.len() > MAX_TRACKED_IPS {
            self.evict_stale_ips();
        }
        (node_banned, ip_banned)
    }

    /// Get a peer's score without triggering decay (for use in immutable contexts).
    pub fn score(&self, node_id: &[u8; 16]) -> i32 {
        self.peers
            .get(node_id)
            .map_or(DEFAULT_REPUTATION, |p| p.score)
    }

    /// Check if a peer is currently banned.
    pub fn is_banned(&self, node_id: &[u8; 16]) -> bool {
        let now = now_secs();
        self.peers.get(node_id).map_or(false, |p| p.is_banned(now))
    }

    /// Get full reputation record for a peer.
    pub fn get_peer(&self, node_id: &[u8; 16]) -> Option<&PeerReputation> {
        self.peers.get(node_id)
    }

    /// Number of tracked peers.
    pub fn tracked_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of currently banned peers.
    pub fn banned_count(&self) -> usize {
        let now = now_secs();
        self.peers.values().filter(|p| p.is_banned(now)).count()
    }

    /// Clear an active ban for a specific peer (manual unban from the UI).
    /// Resets `banned_until` and pulls the score back above the ban
    /// threshold so the peer isn't immediately re-banned by stale
    /// negative score. Returns `true` if the peer had a record. No-op if
    /// the peer is unknown.
    pub fn clear_ban(&mut self, node_id: &[u8; 16]) -> bool {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.banned_until = None;
            if peer.score <= BAN_THRESHOLD {
                peer.score = BAN_THRESHOLD + 1;
            }
            true
        } else {
            false
        }
    }

    /// Clear an active IP-correlation ban (and soften the IP score) so a
    /// manual unban that removes the IP from `banned_ips` is not
    /// immediately re-armed by the next scored event against a still-
    /// banned `IpReputation` row.
    pub fn clear_ip_ban(&mut self, ip: std::net::Ipv4Addr) -> bool {
        let key = ip.octets();
        if let Some(entry) = self.ips.get_mut(&key) {
            entry.banned_until = None;
            if entry.score <= IP_BAN_THRESHOLD {
                entry.score = IP_BAN_THRESHOLD + 1;
            }
            true
        } else {
            false
        }
    }

    /// Mirror a node-identity ban onto an observed IPv4 so periodic
    /// `banned_ips` rebuilds (which re-seed from
    /// `currently_banned_ips`) keep enforcing that address for the
    /// reputation TTL even when the IP is not yet in SourceManager.
    pub fn mirror_node_ban_to_ip(&mut self, ip: std::net::Ipv4Addr) {
        let now = now_secs();
        let key = ip.octets();
        let entry = self
            .ips
            .entry(key)
            .or_insert_with(|| IpReputation::new(key, now));
        entry.last_interaction = now;
        entry.banned_until = Some(now + BAN_DURATION.as_secs());
        if self.ips.len() > MAX_TRACKED_IPS {
            self.evict_stale_ips();
        }
    }

    /// Node identities whose reputation ban has not yet expired.
    pub fn currently_banned_node_ids(&self) -> Vec<[u8; 16]> {
        let now = now_secs();
        self.peers
            .iter()
            .filter(|(_, p)| p.is_banned(now))
            .map(|(id, _)| *id)
            .collect()
    }

    /// IPv4 addresses whose IP-reputation ban has not yet expired.
    pub fn currently_banned_ips(&self) -> Vec<std::net::Ipv4Addr> {
        let now = now_secs();
        self.ips
            .iter()
            .filter(|(_, p)| p.is_banned(now))
            .map(|(octets, _)| std::net::Ipv4Addr::from(*octets))
            .collect()
    }

    /// Apply a manual UI ban so reputation-gated paths and the Trust
    /// badge agree with the persistent ban list. Creates a tracker
    /// entry if needed. Duration matches automatic score bans.
    pub fn apply_manual_ban(&mut self, node_id: &[u8; 16]) {
        let now = now_secs();
        let peer = self
            .peers
            .entry(*node_id)
            .or_insert_with(|| PeerReputation::new(*node_id, now));
        peer.banned_until = Some(now + BAN_DURATION.as_secs());
        peer.last_interaction = now;
        if peer.score > BAN_THRESHOLD {
            peer.score = BAN_THRESHOLD;
        }
    }

    /// Lift bans that have expired.
    pub fn lift_expired_bans(&mut self) {
        let now = now_secs();
        for peer in self.peers.values_mut() {
            if let Some(until) = peer.banned_until {
                if now >= until {
                    peer.banned_until = None;
                    peer.score = (peer.score / 2).max(BAN_THRESHOLD + 1);
                }
            }
        }
        for ip in self.ips.values_mut() {
            if ip.banned_until.is_some_and(|until| now >= until) {
                ip.banned_until = None;
                ip.score = (ip.score / 2).max(IP_BAN_THRESHOLD + 1);
            }
        }
    }

    /// Apply periodic score decay toward zero.
    pub fn maybe_decay(&mut self) {
        let now = now_secs();
        let elapsed = now.saturating_sub(self.last_decay);
        let intervals = (elapsed / DECAY_INTERVAL.as_secs()) as u32;
        if intervals == 0 {
            return;
        }
        self.last_decay = now;
        for peer in self.peers.values_mut() {
            peer.apply_decay(intervals);
        }
        for ip in self.ips.values_mut() {
            ip.apply_decay(intervals);
        }
    }

    /// Save reputation data to disk as JSON.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let persisted = PersistedReputation {
            last_decay: self.last_decay,
            peers: self.peers.values().cloned().collect(),
            ips: self.ips.values().cloned().collect(),
        };
        let json =
            serde_json::to_string(&persisted).map_err(|e| format!("reputation serialize: {e}"))?;
        // Atomic (temp file + fsync + rename) like `known.met` and the
        // credit/key material below — this file is rewritten every 5
        // minutes for the life of any active session, so a crash or
        // power-loss mid-write under a plain truncating `fs::write` would
        // silently wipe the entire peer-reputation/ban database on next
        // launch (a corrupt-JSON `load()` falls back to `Self::new()`,
        // un-banning every flooder/abuser with no error surfaced).
        crate::security::atomic_write(path, json.as_bytes(), false)
            .map_err(|e| format!("reputation write: {e}"))
    }

    /// Load reputation data from disk. Returns a new manager on any error.
    ///
    /// Loaded entries are normalized: `score` is clamped to
    /// `[MIN_REPUTATION, MAX_REPUTATION]` and `banned_until` is
    /// capped to at most `now + BAN_DURATION` (with 1-hour skew
    /// allowance). This prevents a tampered or hand-edited
    /// `reputation.json` from bypassing the runtime invariants
    /// enforced by `apply_event`/`record_event` (e.g. setting
    /// `banned_until = u64::MAX` for a permanent ban, or
    /// `score = i32::MAX` to whitewash a known-bad peer).
    pub fn load(path: &Path) -> Self {
        let data = match std::fs::read_to_string(path) {
            Ok(d) => d,
            // A missing file is the expected first-run state, not a
            // problem worth logging.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::new(),
            Err(e) => {
                tracing::warn!(
                    "reputation load failed to read {}: {e}; starting fresh",
                    path.display()
                );
                return Self::new();
            }
        };

        // Prefer the current wrapped format (carries `last_decay` so decay
        // for elapsed offline time can be applied below); fall back to the
        // legacy bare-array format from before `last_decay` was persisted.
        let (entries, ip_entries, persisted_last_decay) =
            match serde_json::from_str::<PersistedReputation>(&data) {
                Ok(p) => (p.peers, p.ips, Some(p.last_decay)),
                Err(_) => match serde_json::from_str::<Vec<PeerReputation>>(&data) {
                    Ok(e) => (e, Vec::new(), None),
                    Err(e) => {
                        tracing::warn!(
                            "reputation load failed to parse {}: {e}; starting fresh",
                            path.display()
                        );
                        return Self::new();
                    }
                },
            };

        let now = now_secs();
        let max_ban = now.saturating_add(BAN_DURATION.as_secs() + 3600);
        let mut peers = HashMap::with_capacity(entries.len());
        let mut newest_interaction = 0u64;
        for mut entry in entries {
            entry.score = entry.score.clamp(MIN_REPUTATION, MAX_REPUTATION);
            entry.banned_until =
                entry
                    .banned_until
                    .map(|until| if until > max_ban { max_ban } else { until });
            newest_interaction = newest_interaction.max(entry.last_interaction);
            peers.insert(entry.node_id, entry);
        }
        let mut ips = HashMap::with_capacity(ip_entries.len());
        for mut entry in ip_entries {
            entry.score = entry.score.clamp(MIN_REPUTATION, MAX_REPUTATION);
            entry.banned_until =
                entry
                    .banned_until
                    .map(|until| if until > max_ban { max_ban } else { until });
            newest_interaction = newest_interaction.max(entry.last_interaction);
            ips.insert(entry.ip, entry);
        }

        // Decay scores for time elapsed while the app was offline. Without
        // this, a peer whose score cratered right before a long shutdown
        // reappears at the exact same score instead of having decayed
        // toward zero the way it would have if the process had stayed up.
        // Prefer the persisted `last_decay`; for legacy files that never
        // recorded it, fall back to the most recent `last_interaction`
        // across all peers as the best available proxy.
        let last_decay = persisted_last_decay
            .filter(|&d| d <= now)
            .unwrap_or_else(|| newest_interaction.min(now));
        let elapsed = now.saturating_sub(last_decay);
        let intervals = (elapsed / DECAY_INTERVAL.as_secs()) as u32;
        if intervals > 0 {
            for peer in peers.values_mut() {
                peer.apply_decay(intervals);
            }
            for ip in ips.values_mut() {
                ip.apply_decay(intervals);
            }
        }

        let mut mgr = Self {
            peers,
            ips,
            last_decay: now,
        };
        // Defensive: enforce the per-load size cap too in case the
        // file claims more peers than the runtime cap (also a
        // potential memory-exhaustion vector via JSON parse).
        if mgr.peers.len() > MAX_TRACKED_PEERS {
            mgr.evict_stale();
        }
        if mgr.ips.len() > MAX_TRACKED_IPS {
            mgr.evict_stale_ips();
        }
        mgr
    }

    fn evict_stale_ips(&mut self) {
        if self.ips.len() <= MAX_TRACKED_IPS {
            return;
        }
        let now = now_secs();
        let mut entries: Vec<([u8; 4], bool, i32, u64)> = self
            .ips
            .iter()
            .map(|(ip, record)| {
                (
                    *ip,
                    record.is_banned(now),
                    record.score,
                    record.last_interaction,
                )
            })
            .collect();
        // Preserve active bans; otherwise evict lowest-value, stalest rows.
        entries.sort_by_key(|(_, banned, score, last)| (*banned, *score, *last));
        for (ip, _, _, _) in entries.into_iter().take(self.ips.len() - MAX_TRACKED_IPS) {
            self.ips.remove(&ip);
        }
    }

    /// Remove the oldest, lowest-scoring peers to stay under the limit.
    fn evict_stale(&mut self) {
        if self.peers.len() <= MAX_TRACKED_PEERS {
            return;
        }
        let to_remove = self.peers.len() - MAX_TRACKED_PEERS;
        let now = now_secs();

        // A banned peer's score sits at or below `BAN_THRESHOLD` by
        // definition, which is exactly the range naive lowest-score-first
        // eviction targets first — so under table pressure the worst
        // offenders were evicted (and thus silently unbanned, since
        // `is_banned` on an unknown id just returns `false`) before any
        // well-behaved peer. Prefer evicting non-banned peers; only reach
        // into the banned set (soonest-expiring first) if that alone
        // can't free enough slots.
        let mut non_banned: Vec<([u8; 16], i32, u64)> = Vec::new();
        let mut banned: Vec<([u8; 16], u64)> = Vec::new();
        for (id, p) in self.peers.iter() {
            if p.is_banned(now) {
                banned.push((*id, p.banned_until.unwrap_or(0)));
            } else {
                non_banned.push((*id, p.score, p.last_interaction));
            }
        }
        // Sort: lowest score first, oldest interaction first
        non_banned.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));

        let mut removed = 0usize;
        for (id, _, _) in non_banned.iter() {
            if removed >= to_remove {
                break;
            }
            self.peers.remove(id);
            removed += 1;
        }
        if removed < to_remove {
            banned.sort_by(|a, b| a.1.cmp(&b.1));
            for (id, _) in banned.iter() {
                if removed >= to_remove {
                    break;
                }
                self.peers.remove(id);
                removed += 1;
            }
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_now() -> u64 {
        1_700_000_000
    }

    #[test]
    fn default_reputation() {
        let mgr = ReputationManager::new();
        let id = [1u8; 16];
        assert_eq!(mgr.score(&id), DEFAULT_REPUTATION);
    }

    #[test]
    fn score_increases_on_success() {
        let mut mgr = ReputationManager::new();
        let id = [2u8; 16];
        mgr.record_event(&id, ReputationEvent::SuccessfulChunk);
        mgr.record_event(&id, ReputationEvent::SuccessfulChunk);
        mgr.record_event(&id, ReputationEvent::SuccessfulChunk);
        assert!(mgr.score(&id) > 0);
    }

    #[test]
    fn score_decreases_on_failure() {
        let mut mgr = ReputationManager::new();
        let id = [3u8; 16];
        mgr.record_event(&id, ReputationEvent::CorruptData);
        assert!(mgr.score(&id) < 0);
    }

    #[test]
    fn ban_on_low_score() {
        let mut mgr = ReputationManager::new();
        let id = [4u8; 16];
        for _ in 0..10 {
            mgr.record_event(&id, ReputationEvent::CorruptData);
        }
        assert!(mgr.is_banned(&id));
    }

    #[test]
    fn score_clamped() {
        let mut mgr = ReputationManager::new();
        let id = [5u8; 16];
        for _ in 0..2000 {
            mgr.record_event(&id, ReputationEvent::SuccessfulChunk);
        }
        assert_eq!(mgr.score(&id), MAX_REPUTATION);

        let id2 = [6u8; 16];
        for _ in 0..200 {
            mgr.record_event(&id2, ReputationEvent::CorruptData);
        }
        assert_eq!(mgr.score(&id2), MIN_REPUTATION);
    }

    #[test]
    fn peer_not_banned_by_default() {
        let mgr = ReputationManager::new();
        let id = [7u8; 16];
        assert!(!mgr.is_banned(&id));
    }

    #[test]
    fn transfer_counters() {
        let mut mgr = ReputationManager::new();
        let id = [8u8; 16];
        mgr.record_event(&id, ReputationEvent::SuccessfulChunk);
        mgr.record_event(&id, ReputationEvent::SuccessfulChunk);
        mgr.record_event(&id, ReputationEvent::FailedChunk);
        let peer = mgr.get_peer(&id).unwrap();
        assert_eq!(peer.successful_transfers, 2);
        assert_eq!(peer.failed_transfers, 1);
    }

    #[test]
    fn decay_toward_zero() {
        let mut rep = PeerReputation::new([9u8; 16], test_now());
        rep.score = 100;
        rep.apply_decay(10);
        assert!(rep.score < 100);
        assert!(rep.score > 0);

        let mut rep2 = PeerReputation::new([10u8; 16], test_now());
        rep2.score = -100;
        rep2.apply_decay(10);
        assert!(rep2.score > -100);
        assert!(rep2.score < 0);
    }

    #[test]
    fn tracked_count() {
        let mut mgr = ReputationManager::new();
        assert_eq!(mgr.tracked_count(), 0);
        mgr.record_event(&[11u8; 16], ReputationEvent::DhtResponse);
        mgr.record_event(&[12u8; 16], ReputationEvent::DhtResponse);
        assert_eq!(mgr.tracked_count(), 2);
    }

    fn unique_temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ember_reputation_{label}_{}_{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ))
    }

    #[test]
    fn eviction_prefers_non_banned_peers_over_banned() {
        let mut mgr = ReputationManager::new();
        let banned_id = [20u8; 16];
        // Drive one peer into a ban.
        for _ in 0..10 {
            mgr.record_event(&banned_id, ReputationEvent::CorruptData);
        }
        assert!(mgr.is_banned(&banned_id));

        // Fill the map past capacity with well-behaved peers so eviction
        // triggers on the next event.
        for i in 0..MAX_TRACKED_PEERS {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            id[15] = 0xFF; // keep distinct from `banned_id`
            mgr.record_event(&id, ReputationEvent::DhtResponse);
        }

        assert!(
            mgr.is_banned(&banned_id),
            "a banned peer must not be evicted ahead of well-behaved peers"
        );
        assert!(mgr.tracked_count() <= MAX_TRACKED_PEERS);
    }

    #[test]
    fn save_and_load_roundtrip_preserves_last_decay() {
        let path = unique_temp_path("roundtrip");
        let mut mgr = ReputationManager::new();
        mgr.record_event(&[30u8; 16], ReputationEvent::SuccessfulHandshake);
        mgr.save(&path).expect("save reputation");

        let loaded = ReputationManager::load(&path);
        let _ = std::fs::remove_file(&path);

        assert_eq!(loaded.tracked_count(), 1);
        assert_eq!(loaded.score(&[30u8; 16]), SCORE_SUCCESSFUL_HANDSHAKE);
    }

    #[test]
    fn load_applies_decay_for_elapsed_offline_time() {
        let path = unique_temp_path("offline_decay");
        let node_id = [31u8; 16];
        let stale_last_decay = test_now().saturating_sub(10 * DECAY_INTERVAL.as_secs());
        let mut peer = PeerReputation::new(node_id, stale_last_decay);
        peer.score = 500;
        let persisted = PersistedReputation {
            last_decay: stale_last_decay,
            peers: vec![peer],
            ips: Vec::new(),
        };
        std::fs::write(&path, serde_json::to_string(&persisted).unwrap())
            .expect("write persisted reputation");

        let loaded = ReputationManager::load(&path);
        let _ = std::fs::remove_file(&path);

        assert!(
            loaded.score(&node_id) < 500,
            "score should have decayed toward zero for the elapsed offline interval"
        );
    }

    #[test]
    fn load_accepts_legacy_bare_array_format() {
        let path = unique_temp_path("legacy_format");
        let node_id = [32u8; 16];
        let peer = PeerReputation::new(node_id, test_now());
        std::fs::write(&path, serde_json::to_string(&vec![peer]).unwrap())
            .expect("write legacy reputation");

        let loaded = ReputationManager::load(&path);
        let _ = std::fs::remove_file(&path);

        assert_eq!(loaded.tracked_count(), 1);
    }

    #[test]
    fn rotating_node_ids_still_accumulate_ip_reputation() {
        let mut manager = ReputationManager::new();
        let ip = std::net::Ipv4Addr::new(203, 0, 113, 9);
        let mut ip_banned = false;
        for index in 0..25u8 {
            let mut node_id = [0u8; 16];
            node_id[0] = index;
            let (_, newly_ip_banned) =
                manager.record_event_with_ip(&node_id, ip, ReputationEvent::ProtocolViolation);
            ip_banned |= newly_ip_banned;
        }
        assert!(
            ip_banned,
            "rotating free identities must not reset address-level abuse history"
        );
        assert!(manager.currently_banned_ips().contains(&ip));
        assert!(manager.clear_ip_ban(ip));
        assert!(!manager.currently_banned_ips().contains(&ip));
    }

    #[test]
    fn load_returns_fresh_manager_on_corrupt_file() {
        let path = unique_temp_path("corrupt");
        std::fs::write(&path, b"not valid json{{{").expect("write corrupt reputation");

        let loaded = ReputationManager::load(&path);
        let _ = std::fs::remove_file(&path);

        assert_eq!(loaded.tracked_count(), 0);
    }
}
