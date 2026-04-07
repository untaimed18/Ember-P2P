use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

/// How long a ban lasts.
const BAN_DURATION: Duration = Duration::from_secs(24 * 3600);

/// Maximum number of tracked peers (evict oldest low-reputation entries).
const MAX_TRACKED_PEERS: usize = 10_000;

/// Represents a tracked event type for reputation scoring.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReputationEvent {
    SuccessfulChunk,
    FailedChunk,
    CorruptData,
    Timeout,
    SuccessfulHandshake,
    ProtocolViolation,
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
#[derive(Debug, Clone)]
pub struct PeerReputation {
    pub node_id: [u8; 16],
    pub score: i32,
    pub successful_transfers: u64,
    pub failed_transfers: u64,
    pub last_interaction: u64,
    pub first_seen: u64,
    pub banned_until: Option<u64>,
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
        let factor = DECAY_FACTOR.powi(intervals as i32);
        self.score = (self.score as f64 * factor).round() as i32;
        self.score = self.score.clamp(MIN_REPUTATION, MAX_REPUTATION);
    }
}

/// Manages reputation scores for all known peers.
pub struct ReputationManager {
    peers: HashMap<[u8; 16], PeerReputation>,
    last_decay: u64,
}

impl ReputationManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            last_decay: now_secs(),
        }
    }

    /// Record an event for a peer, creating their entry if needed.
    pub fn record_event(&mut self, node_id: &[u8; 16], event: ReputationEvent) {
        let now = now_secs();
        let entry = self.peers.entry(*node_id).or_insert_with(|| {
            PeerReputation::new(*node_id, now)
        });
        entry.apply_event(event, now);

        if self.peers.len() > MAX_TRACKED_PEERS {
            self.evict_stale();
        }
    }

    /// Get a peer's current score, applying decay first.
    pub fn get_score(&mut self, node_id: &[u8; 16]) -> i32 {
        self.maybe_decay();
        self.peers.get(node_id).map_or(DEFAULT_REPUTATION, |p| p.score)
    }

    /// Check if a peer is currently banned.
    pub fn is_banned(&self, node_id: &[u8; 16]) -> bool {
        let now = now_secs();
        self.peers
            .get(node_id)
            .map_or(false, |p| p.is_banned(now))
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
    }

    /// Remove the oldest, lowest-scoring peers to stay under the limit.
    fn evict_stale(&mut self) {
        if self.peers.len() <= MAX_TRACKED_PEERS {
            return;
        }
        let to_remove = self.peers.len() - MAX_TRACKED_PEERS;
        let mut entries: Vec<([u8; 16], i32, u64)> = self
            .peers
            .iter()
            .map(|(id, p)| (*id, p.score, p.last_interaction))
            .collect();
        // Sort: lowest score first, oldest interaction first
        entries.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
        for (id, _, _) in entries.iter().take(to_remove) {
            self.peers.remove(id);
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
        let mut mgr = ReputationManager::new();
        let id = [1u8; 16];
        assert_eq!(mgr.get_score(&id), DEFAULT_REPUTATION);
    }

    #[test]
    fn score_increases_on_success() {
        let mut mgr = ReputationManager::new();
        let id = [2u8; 16];
        mgr.record_event(&id, ReputationEvent::SuccessfulChunk);
        mgr.record_event(&id, ReputationEvent::SuccessfulChunk);
        mgr.record_event(&id, ReputationEvent::SuccessfulChunk);
        assert!(mgr.get_score(&id) > 0);
    }

    #[test]
    fn score_decreases_on_failure() {
        let mut mgr = ReputationManager::new();
        let id = [3u8; 16];
        mgr.record_event(&id, ReputationEvent::CorruptData);
        assert!(mgr.get_score(&id) < 0);
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
        assert_eq!(mgr.get_score(&id), MAX_REPUTATION);

        let id2 = [6u8; 16];
        for _ in 0..200 {
            mgr.record_event(&id2, ReputationEvent::CorruptData);
        }
        assert_eq!(mgr.get_score(&id2), MIN_REPUTATION);
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
}
