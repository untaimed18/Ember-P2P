use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::nat::NatType;

/// Helper that emits a `BrokerEvent` without ever blocking the network
/// task. Earlier code used `event_tx.send(...).await`, which silently
/// deadlocked when the bounded broker channel filled up: every producer
/// in this module is invoked from the same select! loop that drains
/// `broker_rx`, so awaiting on a full channel meant the drain arm could
/// never run. `try_send` always returns immediately; on overflow we drop
/// the event and log it. The broker's periodic `tick()` reaps any
/// orphaned attempt so a dropped event never strands state forever.
fn emit_event(tx: &mpsc::Sender<BrokerEvent>, event: BrokerEvent) {
    if let Err(e) = tx.try_send(event) {
        match e {
            mpsc::error::TrySendError::Full(_) => {
                warn!("Broker event channel full; dropping event (drain stalled?)");
            }
            mpsc::error::TrySendError::Closed(_) => {
                debug!("Broker event channel closed; dropping event");
            }
        }
    }
}

const MAX_ACTIVE_ATTEMPTS: usize = 8;
const RELAY_TIMEOUT: Duration = Duration::from_secs(30);
const ATTEMPT_COOLDOWN: Duration = Duration::from_secs(120);
const ATTEMPT_RESET: Duration = Duration::from_secs(600);
const MAX_ATTEMPTS_PER_SOURCE: u32 = 3;
/// Prefer fresh candidates when picking a relay; older-but-still-retained
/// entries remain until `RELAY_CANDIDATE_PRUNE_MAX_AGE`.
const RELAY_CANDIDATE_PICK_MAX_AGE: Duration = Duration::from_secs(600);
/// Must match `super::RELAY_ATTESTATION_MAX_TTL_SECS` so broker retention
/// cannot outlive (or trail) cryptographically accepted ERAT lifetimes.
const RELAY_CANDIDATE_PRUNE_MAX_AGE: Duration =
    Duration::from_secs(super::RELAY_ATTESTATION_MAX_TTL_SECS);

/// Outcome of a successful broker connection attempt.
pub struct BrokerConnection {
    pub transfer_id: String,
    pub file_hash: [u8; 16],
    pub source_ip: Ipv4Addr,
    pub source_port: u16,
    pub method: ConnectionMethod,
    pub relay_addr: Option<(Ipv4Addr, u16)>,
    pub reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    pub writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
}

impl std::fmt::Debug for BrokerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerConnection")
            .field("transfer_id", &self.transfer_id)
            .field("source_ip", &self.source_ip)
            .field("source_port", &self.source_port)
            .field("method", &self.method)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionMethod {
    PeerRelay,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum AttemptPhase {
    FindRelay,
    RelayConnect,
}

/// Tracks an in-progress LowID-to-LowID connection attempt.
struct ConnectionAttempt {
    transfer_id: String,
    file_hash: [u8; 16],
    source_ip: Ipv4Addr,
    source_port: u16,
    phase: AttemptPhase,
    started: Instant,
    phase_started: Instant,
}

impl ConnectionAttempt {
    fn is_expired(&self) -> bool {
        self.phase_started.elapsed() > RELAY_TIMEOUT
    }
}

/// A candidate peer willing to relay connections for us.
#[derive(Debug, Clone)]
pub struct RelayCandidate {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub attestation_hash: [u8; 32],
    pub ember_hash: Option<[u8; 16]>,
    pub last_seen: Instant,
    pub relay_sessions: u32,
    /// Signed expiry of the ERAT this candidate was admitted with
    /// (`RelayAttestation::expires_at_unix`). `pick_relay_candidate` checks
    /// this directly instead of relying solely on the age-based prune
    /// window: `RELAY_CANDIDATE_PRUNE_MAX_AGE` bounds the *maximum* ERAT
    /// TTL, but a short-TTL attestation can cryptographically expire well
    /// before that window elapses, and the candidate would otherwise stay
    /// pickable (and fail relay admission) until the age prune caught up.
    pub expires_at_unix: u64,
}

/// Execute a QUIC hole-punch connect to the given remote address.
/// Returns the opened bidirectional send/recv streams on success.
pub async fn punch_quic(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    pin: Option<(&[u8], &[u8], [u8; 16])>,
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    let conn = super::quic::connect_pinned(endpoint, addr, "ember-punch", pin)
        .await
        .map_err(|e| format!("QUIC handshake failed with {addr}: {e}"))?;

    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("QUIC open_bi failed: {e}"))?;

    Ok((send, recv))
}

/// Session counters for the LowID-to-LowID broker. Owned by
/// `ConnectionBroker` so the state machine itself is the source of truth
/// for what counts as an "attempt" or "failure" ??? consumers should
/// snapshot via `ConnectionBroker::stats()` rather than incrementing
/// from the outside.
#[derive(Debug, Default, Clone, Copy)]
pub struct BrokerStats {
    pub relay_attempts: u32,
    pub relay_successes: u32,
    pub relay_failures: u32,
}

/// Orchestrates LowID-to-LowID connections by relaying through a third peer.
///
/// Despite the name, no hole punch is attempted here. The sources this path
/// serves are anonymous LowID rows discovered via KAD or a server: they carry
/// no registered Ember identity, so there is no key to sign a v2 punch request
/// with and nothing for the far side to verify. `attempt_low_to_low` therefore
/// starts at [`AttemptPhase::FindRelay`] unconditionally — see the comment
/// there. Friend-to-friend transfers, which *do* have a proven identity, run
/// their own connect-back/punch negotiation over the friend session instead.
pub struct ConnectionBroker {
    attempts: HashMap<String, ConnectionAttempt>,
    cooldowns: HashMap<(Ipv4Addr, u16), (Instant, u32)>,
    relay_candidates: Vec<RelayCandidate>,
    event_tx: mpsc::Sender<BrokerEvent>,
    quic_endpoint: Option<Arc<quinn::Endpoint>>,
    stats: BrokerStats,
}

/// Events emitted by the broker for the main network loop to act on.
#[derive(Debug)]
pub enum BrokerEvent {
    /// Request relay from a peer or server.
    StartRelay {
        attempt_key: String,
        source_ip: Ipv4Addr,
        source_port: u16,
        file_hash: [u8; 16],
        relay_addr: Option<(Ipv4Addr, u16)>,
        relay_attestation_hash: Option<[u8; 32]>,
        relay_ember_hash: Option<[u8; 16]>,
    },
    /// Hole-punch or relay succeeded -- connection ready for download.
    ConnectionReady(BrokerConnection),
    /// All methods exhausted for this source.
    ConnectionFailed {
        transfer_id: String,
        source_ip: Ipv4Addr,
        source_port: u16,
        reason: String,
    },
    /// Spawned relay task reports failure -- broker should emit ConnectionFailed.
    RelayFailed { attempt_key: String, reason: String },
}

impl ConnectionBroker {
    pub fn new(_rendezvous_url: String, event_tx: mpsc::Sender<BrokerEvent>) -> Self {
        Self {
            attempts: HashMap::new(),
            cooldowns: HashMap::new(),
            relay_candidates: Vec::new(),
            event_tx,
            quic_endpoint: None,
            stats: BrokerStats::default(),
        }
    }

    /// Snapshot the broker's session counters. Cheap (`Copy`).
    pub fn stats(&self) -> BrokerStats {
        self.stats
    }

    /// Clone the internal event sender so spawned tasks can report results back.
    pub fn event_sender(&self) -> mpsc::Sender<BrokerEvent> {
        self.event_tx.clone()
    }

    pub fn set_quic_endpoint(&mut self, endpoint: Arc<quinn::Endpoint>) {
        self.quic_endpoint = Some(endpoint);
    }

    pub fn quic_endpoint(&self) -> Option<&Arc<quinn::Endpoint>> {
        self.quic_endpoint.as_ref()
    }

    /// Called when a LowToLowIp situation is detected instead of giving up.
    pub async fn attempt_low_to_low(
        &mut self,
        transfer_id: &str,
        file_hash: [u8; 16],
        source_ip: Ipv4Addr,
        source_port: u16,
        our_nat: NatType,
        _our_external_addr: Option<SocketAddr>,
    ) -> bool {
        let source_key = (source_ip, source_port);

        // Check cooldown
        let mut cooldown_count = 0;
        if let Some((last, count)) = self.cooldowns.get(&source_key) {
            let elapsed = last.elapsed();
            if elapsed < ATTEMPT_COOLDOWN {
                debug!(
                    "Broker: source {}:{} is in cooldown ({} previous attempts)",
                    source_ip, source_port, count
                );
                return false;
            }
            if *count >= MAX_ATTEMPTS_PER_SOURCE && elapsed < ATTEMPT_RESET {
                debug!(
                    "Broker: source {}:{} exceeded max attempts",
                    source_ip, source_port
                );
                return false;
            }
            if elapsed < ATTEMPT_RESET {
                cooldown_count = *count;
            }
        }

        if self.attempts.len() >= MAX_ACTIVE_ATTEMPTS {
            debug!("Broker: too many active attempts ({})", self.attempts.len());
            return false;
        }

        let attempt_key = format!("{}:{}:{}", transfer_id, source_ip, source_port);
        if self.attempts.contains_key(&attempt_key) {
            return false;
        }

        let now = Instant::now();
        self.cooldowns.insert(source_key, (now, cooldown_count + 1));

        // Anonymous LowID sources have no registered Ember identity to sign
        // a v2 punch request, so the broker starts directly at relay.
        let start_phase = AttemptPhase::FindRelay;

        let attempt = ConnectionAttempt {
            transfer_id: transfer_id.to_string(),
            file_hash,
            source_ip,
            source_port,
            phase: start_phase,
            started: now,
            phase_started: now,
        };

        info!(
            "Broker: starting LowID-to-LowID attempt for {}:{} (phase={:?}, nat={:?})",
            source_ip, source_port, start_phase, our_nat
        );

        self.attempts.insert(attempt_key.clone(), attempt);

        let relay_candidate = self.pick_relay_candidate();
        let relay_addr = relay_candidate.map(|c| (c.ip, c.port));
        let relay_attestation_hash = relay_candidate.map(|c| c.attestation_hash);
        let relay_ember_hash = relay_candidate.and_then(|c| c.ember_hash);
        self.stats.relay_attempts = self.stats.relay_attempts.saturating_add(1);
        emit_event(
            &self.event_tx,
            BrokerEvent::StartRelay {
                attempt_key,
                source_ip,
                source_port,
                file_hash,
                relay_addr,
                relay_attestation_hash,
                relay_ember_hash,
            },
        );

        true
    }

    /// Called when a relay attempt fails.
    pub async fn relay_failed(&mut self, attempt_key: &str, reason: &str) {
        if let Some(attempt) = self.attempts.remove(attempt_key) {
            debug!("Broker: relay failed for {attempt_key}: {reason}");
            self.stats.relay_failures = self.stats.relay_failures.saturating_add(1);
            emit_event(
                &self.event_tx,
                BrokerEvent::ConnectionFailed {
                    transfer_id: attempt.transfer_id,
                    source_ip: attempt.source_ip,
                    source_port: attempt.source_port,
                    reason: reason.to_string(),
                },
            );
        }
    }

    /// Called when a relay succeeds.
    pub fn mark_succeeded(&mut self, attempt_key: &str, _method: ConnectionMethod) {
        self.attempts.remove(attempt_key);
        self.stats.relay_successes = self.stats.relay_successes.saturating_add(1);
    }

    /// Add a relay-capable peer discovered via EPX. `expires_at_unix` must
    /// come from the verified `RelayAttestation` this candidate was
    /// admitted with (see `verify_relay_attestation` at the call site) ???
    /// it is the caller's job to have already checked the signature.
    pub fn add_relay_candidate(
        &mut self,
        ip: Ipv4Addr,
        port: u16,
        attestation_hash: [u8; 32],
        ember_hash: Option<[u8; 16]>,
        expires_at_unix: u64,
    ) {
        if let Some(existing) = self
            .relay_candidates
            .iter_mut()
            .find(|c| c.ip == ip && c.port == port)
        {
            existing.attestation_hash = attestation_hash;
            existing.ember_hash = ember_hash;
            existing.last_seen = Instant::now();
            existing.expires_at_unix = expires_at_unix;
            return;
        }
        const MAX_RELAY_CANDIDATES: usize = 50;
        if self.relay_candidates.len() >= MAX_RELAY_CANDIDATES {
            // Evict oldest
            if let Some(oldest_idx) = self
                .relay_candidates
                .iter()
                .enumerate()
                .min_by_key(|(_, c)| c.last_seen)
                .map(|(i, _)| i)
            {
                self.relay_candidates.remove(oldest_idx);
            }
        }
        self.relay_candidates.push(RelayCandidate {
            ip,
            port,
            attestation_hash,
            ember_hash,
            last_seen: Instant::now(),
            relay_sessions: 0,
            expires_at_unix,
        });
    }

    /// Pick the best available relay candidate (fewest sessions, most recent).
    ///
    /// Filters on both the age-based `RELAY_CANDIDATE_PICK_MAX_AGE` window
    /// *and* the candidate's own signed `expires_at_unix` ??? the age window
    /// alone is only an upper bound (aligned to the max ERAT TTL); a
    /// short-TTL attestation can expire well before it, and picking an
    /// already-expired candidate just wastes a relay attempt that the
    /// peer's own `accepts_attestation_hash` will reject anyway.
    fn pick_relay_candidate(&self) -> Option<&RelayCandidate> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.relay_candidates
            .iter()
            .filter(|c| {
                c.last_seen.elapsed() < RELAY_CANDIDATE_PICK_MAX_AGE && c.expires_at_unix > now_unix
            })
            .min_by_key(|c| (c.relay_sessions, c.last_seen.elapsed().as_secs()))
    }

    /// Clean up expired attempts. Called periodically from the main loop.
    pub async fn tick(&mut self) {
        let expired: Vec<String> = self
            .attempts
            .iter()
            .filter(|(_, a)| a.is_expired())
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired {
            if self.attempts.contains_key(&key) {
                info!("Broker: relay timed out for {key}");
                self.relay_failed(&key, "timeout").await;
            }
        }

        // Prune stale relay candidates (aligned with ERAT max TTL) and any
        // whose own signed expiry has already passed, even if still within
        // the age window (a short-TTL ERAT expires before the max-age bound).
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.relay_candidates.retain(|c| {
            c.last_seen.elapsed() < RELAY_CANDIDATE_PRUNE_MAX_AGE && c.expires_at_unix > now_unix
        });

        // Prune old cooldowns
        self.cooldowns
            .retain(|_, (ts, _)| ts.elapsed() < ATTEMPT_RESET);
    }

    pub fn active_attempts(&self) -> usize {
        self.attempts.len()
    }

    pub fn relay_candidate_count(&self) -> usize {
        self.relay_candidates.len()
    }

    /// Age in seconds of the longest-running in-flight attempt, if any.
    /// Surfaced in Ember diagnostics so a broker attempt stuck across both
    /// the punch and relay phases is observable rather than silent.
    pub fn oldest_attempt_age_secs(&self) -> Option<u64> {
        self.attempts
            .values()
            .map(|a| a.started.elapsed().as_secs())
            .max()
    }

    /// Look up attempt metadata. Returns (transfer_id, file_hash, source_ip, source_port).
    pub fn get_attempt_info(&self, attempt_key: &str) -> Option<(String, [u8; 16], Ipv4Addr, u16)> {
        self.attempts.get(attempt_key).map(|a| {
            (
                a.transfer_id.clone(),
                a.file_hash,
                a.source_ip,
                a.source_port,
            )
        })
    }

    /// Increment the relay session count for a relay candidate after a successful relay.
    pub fn increment_relay_sessions(&mut self, ip: Ipv4Addr, port: u16) {
        if let Some(candidate) = self
            .relay_candidates
            .iter_mut()
            .find(|c| c.ip == ip && c.port == port)
        {
            candidate.relay_sessions += 1;
            debug!(
                "Broker: incremented relay_sessions for {}:{} to {}",
                ip, port, candidate.relay_sessions
            );
        }
    }

    /// Transition an attempt to the RelayConnect phase.
    pub fn set_relay_phase(&mut self, attempt_key: &str) {
        if let Some(attempt) = self.attempts.get_mut(attempt_key) {
            attempt.phase = AttemptPhase::RelayConnect;
            attempt.phase_started = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn attempt_respects_cooldown() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);

        let started = broker
            .attempt_low_to_low(
                "t1",
                [1u8; 16],
                Ipv4Addr::new(1, 2, 3, 4),
                4662,
                NatType::PortRestricted,
                Some("5.6.7.8:9999".parse().unwrap()),
            )
            .await;
        assert!(started);

        // Second attempt to same source should fail (cooldown)
        let started2 = broker
            .attempt_low_to_low(
                "t1",
                [1u8; 16],
                Ipv4Addr::new(1, 2, 3, 4),
                4662,
                NatType::PortRestricted,
                Some("5.6.7.8:9999".parse().unwrap()),
            )
            .await;
        assert!(!started2);

        // Drain events
        while rx.try_recv().is_ok() {}
    }

    #[tokio::test]
    async fn symmetric_nat_starts_relay() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);

        broker
            .attempt_low_to_low(
                "t2",
                [2u8; 16],
                Ipv4Addr::new(10, 20, 30, 40),
                4662,
                NatType::Symmetric,
                Some("5.6.7.8:9999".parse().unwrap()),
            )
            .await;

        if let Some(event) = rx.recv().await {
            assert!(matches!(event, BrokerEvent::StartRelay { .. }));
        }
    }

    #[tokio::test]
    async fn punchable_nat_without_target_identity_starts_relay() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);

        broker
            .attempt_low_to_low(
                "t3",
                [3u8; 16],
                Ipv4Addr::new(10, 20, 30, 40),
                4662,
                NatType::PortRestricted,
                Some("5.6.7.8:9999".parse().unwrap()),
            )
            .await;

        if let Some(event) = rx.recv().await {
            assert!(matches!(event, BrokerEvent::StartRelay { .. }));
        }
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn relay_candidate_management() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let future_expiry = unix_now() + 600;

        broker.add_relay_candidate(
            Ipv4Addr::new(1, 1, 1, 1),
            4662,
            [1u8; 32],
            None,
            future_expiry,
        );
        broker.add_relay_candidate(
            Ipv4Addr::new(2, 2, 2, 2),
            4663,
            [2u8; 32],
            None,
            future_expiry,
        );
        assert_eq!(broker.relay_candidate_count(), 2);

        // Duplicate is deduplicated
        broker.add_relay_candidate(
            Ipv4Addr::new(1, 1, 1, 1),
            4662,
            [3u8; 32],
            None,
            future_expiry,
        );
        assert_eq!(broker.relay_candidate_count(), 2);
        assert_eq!(
            broker
                .relay_candidates
                .iter()
                .find(|c| c.ip == Ipv4Addr::new(1, 1, 1, 1) && c.port == 4662)
                .map(|c| c.attestation_hash),
            Some([3u8; 32])
        );

        let picked = broker.pick_relay_candidate();
        assert!(picked.is_some());
    }

    /// A candidate whose signed `expires_at_unix` has already passed must
    /// never be picked, even though it's well within the age-based
    /// `RELAY_CANDIDATE_PICK_MAX_AGE` window ??? the age window is only an
    /// upper bound (aligned to the max ERAT TTL), not a substitute for
    /// checking the attestation's own shorter-lived expiry.
    #[test]
    fn pick_relay_candidate_skips_expired_attestation() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);

        broker.add_relay_candidate(
            Ipv4Addr::new(9, 9, 9, 9),
            4662,
            [9u8; 32],
            None,
            unix_now().saturating_sub(1),
        );
        assert_eq!(broker.relay_candidate_count(), 1);
        assert!(broker.pick_relay_candidate().is_none());

        // A fresh, unexpired candidate is still pickable.
        broker.add_relay_candidate(
            Ipv4Addr::new(8, 8, 8, 8),
            4662,
            [8u8; 32],
            None,
            unix_now() + 600,
        );
        let picked = broker.pick_relay_candidate();
        assert_eq!(picked.map(|c| c.ip), Some(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[tokio::test]
    async fn anonymous_lowid_emits_only_one_relay_event() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);

        broker
            .attempt_low_to_low(
                "t4",
                [4u8; 16],
                Ipv4Addr::new(10, 20, 30, 40),
                4662,
                NatType::PortRestricted,
                Some("5.6.7.8:9999".parse().unwrap()),
            )
            .await;

        assert!(matches!(
            rx.recv().await,
            Some(BrokerEvent::StartRelay { .. })
        ));
        assert!(rx.try_recv().is_err());
    }
}
