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
    /// Which relay this attempt was handed to, so its outcome can be charged
    /// back to that candidate. Without this the broker learned nothing from a
    /// failure and would pick the same dead relay again immediately.
    relay: Option<(Ipv4Addr, u16)>,
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
    /// The attestation this candidate was admitted with, kept whole rather
    /// than reduced to its hash so it can be forwarded to a friend whose own
    /// swarm never produced one (see `gossipable_attestations`). The hash
    /// alone is useless to a third party: they cannot verify a signature they
    /// do not have.
    pub attestation: super::RelayAttestation,
    pub ember_hash: Option<[u8; 16]>,
    /// Consecutive failed relay attempts against this candidate, reset by any
    /// success.
    ///
    /// An attestation only proves that whoever signed it *claims* the address;
    /// nothing proves they hold it. The pinned QUIC handshake catches the lie,
    /// but only at the moment of use — so without recording the outcome the
    /// broker kept choosing a candidate that could never work, and preferring
    /// it, since [`Self::pick_relay_candidate`] ranks fewest-sessions first and
    /// a fabricated entry has carried none.
    pub failures: u32,
    /// Which peer handed us this attestation, or `None` when we saw it on a
    /// swarm exchange rather than a friend's forward. Used only to bound one
    /// introducer's share of the list, never to decide trust — that rests
    /// entirely on the attestation's own signature.
    pub introduced_by: Option<[u8; 16]>,
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
    RelayFailed {
        attempt_key: String,
        reason: String,
        /// Whether the relay itself is to blame, and so should have the failure
        /// counted against it.
        ///
        /// Several of these are raised by our own setup — no QUIC endpoint, no
        /// attestation hash to present, no candidate at all — and say nothing
        /// about the peer. Charging those to a relay would evict a perfectly
        /// good one after three of our own stumbles.
        relay_at_fault: bool,
    },
}

impl ConnectionBroker {
    /// Total relay candidates retained.
    const MAX_RELAY_CANDIDATES: usize = 50;
    /// Ceiling on how many of those any one introducer may account for.
    ///
    /// Set well below the total so a hostile friend forwarding self-minted
    /// attestations cannot displace the relays we learned elsewhere, while
    /// still leaving room for a friend that legitimately knows several.
    const MAX_CANDIDATES_PER_INTRODUCER: usize = 8;
    /// Consecutive failures before a relay candidate is dropped.
    ///
    /// More than one, because a working relay can fail transiently — it may be
    /// briefly saturated, or restarting — and evicting on a single miss would
    /// throw away good relays. Low enough that a fabricated entry, which fails
    /// every time, is gone after a couple of attempts.
    const MAX_CANDIDATE_FAILURES: u32 = 3;

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

        let relay_candidate = self.pick_relay_candidate();
        let relay_addr = relay_candidate.map(|c| (c.ip, c.port));
        let relay_attestation_hash = relay_candidate.map(|c| c.attestation_hash);
        let relay_ember_hash = relay_candidate.and_then(|c| c.ember_hash);

        let attempt = ConnectionAttempt {
            transfer_id: transfer_id.to_string(),
            file_hash,
            source_ip,
            source_port,
            phase: start_phase,
            started: now,
            phase_started: now,
            relay: relay_addr,
        };

        info!(
            "Broker: starting LowID-to-LowID attempt for {}:{} (phase={:?}, nat={:?})",
            source_ip, source_port, start_phase, our_nat
        );

        self.attempts.insert(attempt_key.clone(), attempt);

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
    pub async fn relay_failed(&mut self, attempt_key: &str, reason: &str, relay_at_fault: bool) {
        if let Some(attempt) = self.attempts.remove(attempt_key) {
            debug!("Broker: relay failed for {attempt_key}: {reason}");
            self.stats.relay_failures = self.stats.relay_failures.saturating_add(1);
            if relay_at_fault {
                if let Some((ip, port)) = attempt.relay {
                    self.penalise_relay_candidate(ip, port);
                }
            }
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
        if let Some(attempt) = self.attempts.remove(attempt_key) {
            if let Some((ip, port)) = attempt.relay {
                // Clears the count rather than decrementing it: a relay that
                // just carried a connection has proved itself, and occasional
                // failures against a working relay should not accumulate into
                // an eviction.
                if let Some(c) = self
                    .relay_candidates
                    .iter_mut()
                    .find(|c| c.ip == ip && c.port == port)
                {
                    c.failures = 0;
                }
            }
        }
        self.stats.relay_successes = self.stats.relay_successes.saturating_add(1);
    }

    /// Charge a failed attempt to the relay that was tried, dropping it once it
    /// has failed [`Self::MAX_CANDIDATE_FAILURES`] times in a row.
    ///
    /// This is what stops a fabricated attestation from capturing relay
    /// selection. Anyone can sign a claim over an address they do not hold, and
    /// such an entry looks *better* than a real relay to
    /// [`Self::pick_relay_candidate`] — no sessions carried, freshly seen — so
    /// before this, one peer forwarding a handful of them could take over every
    /// choice, fail each time, and be chosen again straight away.
    fn penalise_relay_candidate(&mut self, ip: Ipv4Addr, port: u16) {
        let Some(idx) = self
            .relay_candidates
            .iter()
            .position(|c| c.ip == ip && c.port == port)
        else {
            return;
        };
        self.relay_candidates[idx].failures =
            self.relay_candidates[idx].failures.saturating_add(1);
        let failures = self.relay_candidates[idx].failures;
        if failures >= Self::MAX_CANDIDATE_FAILURES {
            info!(
                "Broker: dropping relay candidate {ip}:{port} after {failures} consecutive failures"
            );
            self.relay_candidates.remove(idx);
        } else {
            debug!("Broker: relay candidate {ip}:{port} now at {failures} consecutive failure(s)");
        }
    }

    /// Add a relay-capable peer discovered via EPX. `expires_at_unix` must
    /// come from the verified `RelayAttestation` this candidate was
    /// admitted with (see `verify_relay_attestation` at the call site) ???
    /// it is the caller's job to have already checked the signature.
    /// `introduced_by` is the peer that handed us this attestation, which is
    /// *not* the relay it names — a friend forwards attestations it did not
    /// sign. It exists only to bound one introducer's share of the list; see
    /// [`Self::MAX_CANDIDATES_PER_INTRODUCER`].
    pub fn add_relay_candidate(
        &mut self,
        attestation: super::RelayAttestation,
        ember_hash: Option<[u8; 16]>,
        introduced_by: Option<[u8; 16]>,
    ) {
        // Address, port, expiry and hash all come from the attestation rather
        // than from separate arguments: they are signed fields, so accepting
        // them alongside it would create a set of parameters that can
        // contradict each other and a candidate that does not match the
        // credential it was admitted with.
        let ip = attestation.relay_ip;
        let port = attestation.relay_port;
        let expires_at_unix = attestation.expires_at_unix;
        let attestation_hash = super::relay_attestation_hash(&attestation);
        if let Some(existing) = self
            .relay_candidates
            .iter_mut()
            .find(|c| c.ip == ip && c.port == port)
        {
            existing.attestation_hash = attestation_hash;
            existing.attestation = attestation;
            existing.ember_hash = ember_hash;
            existing.last_seen = Instant::now();
            existing.expires_at_unix = expires_at_unix;
            // `failures` deliberately survives a refresh. Gossip re-sends the
            // same set every few ticks, so clearing it here would let a
            // fabricated candidate wipe its own record faster than it can
            // accumulate one and stay at the front of the queue for ever.
            return;
        }
        // A single introducer must not be able to own the list. Attestations
        // are self-signed, so one peer can mint as many valid ones as it likes
        // from throwaway keys; with only global oldest-first eviction it could
        // refresh a full set every throttle interval and crowd out every relay
        // learned first-hand, steering relayed transfers through addresses it
        // chose. Capping its share keeps the rest of the list reachable.
        if let Some(source) = introduced_by {
            let mut theirs: Vec<usize> = self
                .relay_candidates
                .iter()
                .enumerate()
                .filter(|(_, c)| c.introduced_by == Some(source))
                .map(|(i, _)| i)
                .collect();
            while theirs.len() >= Self::MAX_CANDIDATES_PER_INTRODUCER {
                // Evict this introducer's own oldest rather than refusing, so a
                // friend whose relays genuinely rotate still stays current.
                let oldest = theirs
                    .iter()
                    .copied()
                    .min_by_key(|&i| self.relay_candidates[i].last_seen);
                match oldest {
                    Some(idx) => {
                        self.relay_candidates.remove(idx);
                        theirs = self
                            .relay_candidates
                            .iter()
                            .enumerate()
                            .filter(|(_, c)| c.introduced_by == Some(source))
                            .map(|(i, _)| i)
                            .collect();
                    }
                    None => break,
                }
            }
        }
        if self.relay_candidates.len() >= Self::MAX_RELAY_CANDIDATES {
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
            attestation,
            ember_hash,
            failures: 0,
            introduced_by,
            last_seen: Instant::now(),
            relay_sessions: 0,
            expires_at_unix,
        });
    }

    /// Attestations worth forwarding to a friend, newest first and capped at
    /// the wire limit.
    ///
    /// Only unexpired ones are offered: a friend cannot use an attestation
    /// that its own `verify_relay_attestation` will reject, and sending it
    /// would just be noise. This is deliberately *all* we know rather than
    /// only what we signed ourselves — the point is that a pair with no swarm
    /// in common can still learn relays through whichever of them has peers.
    pub fn gossipable_attestations(&self, now_unix: u64) -> Vec<super::RelayAttestation> {
        let mut fresh: Vec<&RelayCandidate> = self
            .relay_candidates
            .iter()
            .filter(|c| c.expires_at_unix > now_unix)
            .collect();
        fresh.sort_by_key(|c| c.last_seen.elapsed());
        fresh
            .into_iter()
            .take(super::MAX_RELAY_ATTESTATIONS)
            .map(|c| c.attestation.clone())
            .collect()
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
            // Failures rank ahead of everything else. A candidate that has just
            // failed must not keep winning on "carried no sessions and seen
            // most recently", which is precisely how a fabricated entry used to
            // outrank a relay that demonstrably works.
            .min_by_key(|c| (c.failures, c.relay_sessions, c.last_seen.elapsed().as_secs()))
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
                // The relay's account: it was asked and did not answer in time.
                self.relay_failed(&key, "timeout", true).await;
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

    /// The broker never inspects a signature — admission already verified it
    /// (`verify_relay_attestation` at the call site), so an unsigned stand-in
    /// exercises the storage and selection logic faithfully.
    fn attestation(
        ip: Ipv4Addr,
        port: u16,
        expires_at_unix: u64,
    ) -> crate::network::ember::RelayAttestation {
        crate::network::ember::RelayAttestation {
            ed25519_pubkey: [0u8; 32],
            relay_ip: ip,
            relay_port: port,
            expires_at_unix,
            capability_bits: crate::network::ember::RELAY_ATTESTATION_CAP_RELAY_V1,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn relay_candidate_management() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let future_expiry = unix_now() + 600;

        broker.add_relay_candidate(
            attestation(Ipv4Addr::new(1, 1, 1, 1), 4662, future_expiry),
            None,
            None,
        );
        broker.add_relay_candidate(
            attestation(Ipv4Addr::new(2, 2, 2, 2), 4663, future_expiry),
            None,
            None,
        );
        assert_eq!(broker.relay_candidate_count(), 2);

        // Re-admitting the same relay refreshes the entry rather than adding a
        // second one, and the stored credential is the newer attestation — not
        // the one the candidate was first seen with.
        let refreshed = attestation(Ipv4Addr::new(1, 1, 1, 1), 4662, future_expiry + 60);
        broker.add_relay_candidate(refreshed.clone(), None, None);
        assert_eq!(broker.relay_candidate_count(), 2);
        let stored = broker
            .relay_candidates
            .iter()
            .find(|c| c.ip == Ipv4Addr::new(1, 1, 1, 1) && c.port == 4662)
            .expect("candidate present");
        assert_eq!(stored.attestation, refreshed);
        assert_eq!(stored.expires_at_unix, future_expiry + 60);
        assert_eq!(
            stored.attestation_hash,
            crate::network::ember::relay_attestation_hash(&refreshed)
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

        let expired = unix_now().saturating_sub(1);
        broker.add_relay_candidate(attestation(Ipv4Addr::new(9, 9, 9, 9), 4662, expired), None, None);
        assert_eq!(broker.relay_candidate_count(), 1);
        assert!(broker.pick_relay_candidate().is_none());

        // A fresh, unexpired candidate is still pickable.
        let fresh = unix_now() + 600;
        broker.add_relay_candidate(attestation(Ipv4Addr::new(8, 8, 8, 8), 4662, fresh), None, None);
        let picked = broker.pick_relay_candidate();
        assert_eq!(picked.map(|c| c.ip), Some(Ipv4Addr::new(8, 8, 8, 8)));
    }

    /// What we forward to a friend is everything still valid, not only what we
    /// signed — a friend with no swarm of its own is exactly who benefits from
    /// relays we learned elsewhere. Expired entries are withheld because the
    /// recipient's own verification would reject them anyway.
    #[test]
    fn gossipable_attestations_offers_fresh_candidates_only() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let now = unix_now();
        let fresh = now + 600;
        let stale = now.saturating_sub(1);

        broker.add_relay_candidate(attestation(Ipv4Addr::new(1, 1, 1, 1), 4662, fresh), None, None);
        broker.add_relay_candidate(attestation(Ipv4Addr::new(2, 2, 2, 2), 4663, stale), None, None);

        let offer = broker.gossipable_attestations(now);
        assert_eq!(offer.len(), 1);
        assert_eq!(offer[0].relay_ip, Ipv4Addr::new(1, 1, 1, 1));
    }

    /// The offer is capped at the wire limit so a well-connected node cannot
    /// build a block the receiver will refuse to parse.
    #[test]
    fn gossipable_attestations_respects_the_wire_cap() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let now = unix_now();
        let fresh = now + 600;

        for i in 0..(crate::network::ember::MAX_RELAY_ATTESTATIONS as u8 + 5) {
            broker.add_relay_candidate(attestation(Ipv4Addr::new(10, 0, 0, i), 4662, fresh), None, None);
        }

        assert_eq!(
            broker.gossipable_attestations(now).len(),
            crate::network::ember::MAX_RELAY_ATTESTATIONS
        );
    }

    /// A fabricated attestation names an address its signer does not hold, and
    /// used to look *better* than a working relay: no sessions carried, freshly
    /// seen. Nothing recorded the outcome of using one, so the broker chose it
    /// again on the next attempt and LowID relaying stalled behind a candidate
    /// that could never complete a pinned handshake.
    #[test]
    fn a_relay_that_keeps_failing_stops_being_chosen_and_is_dropped() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let fresh = unix_now() + 600;
        let bogus = Ipv4Addr::new(203, 0, 113, 5);
        let working = Ipv4Addr::new(198, 51, 100, 7);

        // The working relay has carried traffic; the fabricated one has not,
        // which is exactly why it wins on the session count alone.
        broker.add_relay_candidate(attestation(working, 4662, fresh), None, None);
        if let Some(c) = broker.relay_candidates.iter_mut().find(|c| c.ip == working) {
            c.relay_sessions = 2;
        }
        broker.add_relay_candidate(attestation(bogus, 4662, fresh), None, None);

        assert_eq!(
            broker.pick_relay_candidate().map(|c| c.ip),
            Some(bogus),
            "precondition: an unused candidate is preferred"
        );

        // One failure is enough to send it behind the relay that works.
        broker.penalise_relay_candidate(bogus, 4662);
        assert_eq!(
            broker.pick_relay_candidate().map(|c| c.ip),
            Some(working),
            "a failing candidate must not keep winning selection"
        );

        // And it is dropped rather than lingering to be retried for ever.
        for _ in 1..ConnectionBroker::MAX_CANDIDATE_FAILURES {
            broker.penalise_relay_candidate(bogus, 4662);
        }
        assert!(
            !broker.relay_candidates.iter().any(|c| c.ip == bogus),
            "a candidate that always fails must be evicted"
        );
        assert!(
            broker.relay_candidates.iter().any(|c| c.ip == working),
            "the working relay must survive"
        );
    }

    /// Only the relay's own failures count against it. Several `RelayFailed`
    /// events are raised by our own setup — no QUIC endpoint, no attestation
    /// hash, no candidate — and blaming the peer for those would evict working
    /// relays after three of our stumbles, shrinking the pool exactly when
    /// LowID transfers need it.
    #[tokio::test]
    async fn our_own_setup_failures_do_not_count_against_a_relay() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let ip = Ipv4Addr::new(198, 51, 100, 3);
        broker.add_relay_candidate(attestation(ip, 4662, unix_now() + 600), None, None);

        for _ in 0..(ConnectionBroker::MAX_CANDIDATE_FAILURES + 2) {
            broker.attempt_low_to_low(
                "t-local",
                [9u8; 16],
                Ipv4Addr::new(10, 0, 0, 1),
                4662,
                NatType::Symmetric,
                Some("5.6.7.8:9999".parse().unwrap()),
            )
            .await;
            broker
                .relay_failed("t-local:10.0.0.1:4662", "no QUIC endpoint", false)
                .await;
            // The source cooldown would refuse a second attempt otherwise.
            broker.cooldowns.clear();
        }

        let candidate = broker.relay_candidates.iter().find(|c| c.ip == ip);
        assert_eq!(
            candidate.map(|c| c.failures),
            Some(0),
            "a relay must not be blamed for failures on our side"
        );
    }

    /// Gossip re-sends the same set repeatedly, so a refresh must not be a way
    /// to launder a failure record — otherwise a fabricated candidate resets
    /// its count faster than it can earn one and never ages out.
    #[test]
    fn refreshing_a_candidate_does_not_clear_its_failures() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let fresh = unix_now() + 600;
        let ip = Ipv4Addr::new(203, 0, 113, 9);

        broker.add_relay_candidate(attestation(ip, 4662, fresh), None, None);
        broker.penalise_relay_candidate(ip, 4662);
        broker.add_relay_candidate(attestation(ip, 4662, fresh + 60), None, None);

        assert_eq!(
            broker
                .relay_candidates
                .iter()
                .find(|c| c.ip == ip)
                .map(|c| c.failures),
            Some(1)
        );
    }

    /// Attestations are self-signed, so one peer can mint unlimited valid ones
    /// from throwaway keys. With only global oldest-first eviction it could
    /// refresh a full set every throttle interval and own the whole list,
    /// steering relayed transfers through addresses of its choosing.
    #[test]
    fn one_introducer_cannot_crowd_out_the_whole_candidate_list() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let fresh = unix_now() + 600;
        let hostile = [0xAAu8; 16];

        // Learned elsewhere — a swarm exchange, with no introducer recorded.
        broker.add_relay_candidate(attestation(Ipv4Addr::new(1, 1, 1, 1), 4662, fresh), None, None);

        for i in 0..40u8 {
            broker.add_relay_candidate(
                attestation(Ipv4Addr::new(10, 0, 0, i), 4662, fresh),
                None,
                Some(hostile),
            );
        }

        let theirs = broker
            .relay_candidates
            .iter()
            .filter(|c| c.introduced_by == Some(hostile))
            .count();
        assert_eq!(
            theirs,
            ConnectionBroker::MAX_CANDIDATES_PER_INTRODUCER,
            "one introducer must not exceed its share"
        );
        assert!(
            broker
                .relay_candidates
                .iter()
                .any(|c| c.ip == Ipv4Addr::new(1, 1, 1, 1)),
            "the first-hand candidate must survive the flood"
        );
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
