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
/// How long a relay that declined to serve us is skipped. Long, because the
/// usual reason is that we are not its friend, which does not change often;
/// finite, because friendship can.
const RELAY_REFUSAL_BACKOFF: Duration = Duration::from_secs(3600);
/// How long a relay that answered it is at capacity is skipped. Short, because
/// its sessions end and free slots; without it a busy friend relay stays the
/// first pick and every further source spends an attempt on the same refusal.
const RELAY_BUSY_BACKOFF: Duration = Duration::from_secs(60);
/// Attempts one relay is asked to carry at once: the sessions it holds for one
/// requester. A burst past that found its handshake and session limits, which
/// cost each source an attempt and could evict the relay as unreachable.
const MAX_ATTEMPTS_PER_RELAY: usize = super::relay::MAX_RELAY_SESSIONS_PER_REQUESTER;
/// Prefer fresh candidates when picking a relay; older-but-still-retained
/// entries remain until `RELAY_CANDIDATE_PRUNE_MAX_AGE`.
const RELAY_CANDIDATE_PICK_MAX_AGE: Duration = Duration::from_secs(600);
/// Must match `super::RELAY_ATTESTATION_MAX_TTL_SECS` so broker retention
/// cannot outlive (or trail) cryptographically accepted ERAT lifetimes.
const RELAY_CANDIDATE_PRUNE_MAX_AGE: Duration =
    Duration::from_secs(super::RELAY_ATTESTATION_MAX_TTL_SECS);

/// What a relay needs to reach a source beyond the address it is known by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayTarget {
    /// The source's advertised QUIC port. Unknown for eMule KAD sources, whose
    /// records have nowhere to carry one; the relay then dials the TCP port,
    /// which is where the source's QUIC endpoint binds when it can.
    pub quic_port: Option<u16>,
    /// The source's Ember node id, for a relay that pins its dial to it.
    pub node_id: Option<[u8; 16]>,
}

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
            .field("relay_addr", &self.relay_addr)
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
    /// The relay has connected us and the source is being greeted, so a
    /// timeout now is the source's silence, not the relay's.
    Greeting,
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
    ///
    /// The third element is the ERAT signer's Ed25519 pubkey. Two candidates
    /// can claim the same IP:port (a forged attestation does not prove
    /// possession), so success and failure must be charged to the signer we
    /// actually picked, not to the first row at that address.
    relay: Option<(Ipv4Addr, u16, [u8; 32])>,
    /// The attestation hash the request to that relay presented. A refusal
    /// answers this attestation, which may no longer be the candidate's.
    relay_attestation_hash: Option<[u8; 32]>,
}

impl ConnectionAttempt {
    fn is_expired(&self) -> bool {
        self.phase_started.elapsed() > RELAY_TIMEOUT
    }

    fn time_left(&self) -> Duration {
        RELAY_TIMEOUT.saturating_sub(self.phase_started.elapsed())
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
    /// broker kept choosing a candidate that could never work, freshly gossiped
    /// as a fabricated entry always is.
    pub failures: u32,
    /// Until when this relay is skipped because it declined to serve us.
    ///
    /// A relay carries only its friends' traffic, and attestations reach us
    /// through public EPX, so most candidates will always say no. That is a
    /// working relay answering correctly, so it is not a failure to evict it
    /// for, but picking it again straight away only spent the source's
    /// attempts on a relay that cannot help. Set when the relay answers
    /// `REJECT_AUTH`; cleared when it carries a session.
    pub refused_until: Option<Instant>,
    /// Until when this relay is skipped because it answered `REJECT_CAPACITY`.
    /// Kept apart from `refused_until` so a re-signed attestation, which lifts
    /// a friend's refusal, does not lift this too.
    pub busy_until: Option<Instant>,
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

/// [`punch_quic`] for callers that hold their raw Ed25519 identity secret and
/// the peer's already-authenticated Ember node id, rather than DER material.
///
/// `punch_quic`'s `pin` tuple wants *our* certificate and key in DER, which is
/// one derivation removed from what punch call sites actually carry — the
/// 32-byte identity secret. That gap is why those sites kept passing `None`
/// even though they had proven the peer's identity moments earlier, leaving
/// the connection bound to no particular node. It has already been got wrong
/// in the other direction too, by passing raw identity key bytes through as if
/// they were DER, which rustls rejected on every pinned attempt. Deriving the
/// cert here (cheap and deterministic) makes the authenticated path the
/// shorter one to write, so `None` stays reserved for genuine first contact.
///
/// `expected_node_id` must be the peer's Ember hash, which is
/// `BLAKE3(ed25519_pub)[..16]` — the exact value `EmberCertVerifier` recomputes
/// from the presented certificate's real SubjectPublicKeyInfo.
pub async fn punch_quic_pinned(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    our_secret_key: &[u8; 32],
    expected_node_id: [u8; 16],
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    let (cert_der, key_der) = super::quic::generate_self_signed_cert(our_secret_key)
        .map_err(|e| format!("could not derive our QUIC certificate: {e}"))?;
    punch_quic(
        endpoint,
        addr,
        Some((&cert_der, &key_der, expected_node_id)),
    )
    .await
}

/// Run `hello` on a relayed stream within `time_left` of its attempt and report
/// the outcome to the broker loop.
///
/// Returns the Hello's result only once the loop has confirmed the attempt was
/// still live, so the stream reaches the download exactly when the attempt
/// counted as a success. Both reports are awaited sends: this runs off the loop
/// that drains `event_tx`, and a dropped `RelayGreeted` would leave a working
/// connection to be failed by the timeout.
pub async fn greet_within_attempt<T>(
    hello: impl std::future::Future<Output = anyhow::Result<T>>,
    time_left: Duration,
    attempt_key: String,
    event_tx: &mpsc::Sender<BrokerEvent>,
) -> Option<T> {
    let greeted = tokio::time::timeout(time_left, hello)
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("no answer within the attempt's time")));
    match greeted {
        Ok(value) => {
            let (live, verdict) = tokio::sync::oneshot::channel();
            if event_tx
                .send(BrokerEvent::RelayGreeted { attempt_key, live })
                .await
                .is_err()
            {
                return None;
            }
            verdict.await.unwrap_or(false).then_some(value)
        }
        Err(e) => {
            debug!("Broker: Ember client Hello failed for {attempt_key}: {e}");
            // Fails the attempt, so the source is not left parked as relayed.
            // Not the relay's fault as far as we can tell: the source may be
            // gone.
            let _ = event_tx
                .send(BrokerEvent::RelayFailed {
                    attempt_key,
                    reason: format!("Hello over the relay failed: {e}"),
                    relay_at_fault: false,
                    refused_us: false,
                    relay_busy: false,
                })
                .await;
            None
        }
    }
}

/// Session counters for the LowID-to-LowID broker. Owned by
/// `ConnectionBroker` so the state machine itself is the source of truth
/// for what counts as an "attempt" or "failure" — consumers should
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
    /// Our friends' Ember hashes, read when an attempt picks a relay.
    friend_hashes: Option<crate::app_state::SharedFriendHashes>,
    /// The friend set as of the last pick; see [`Self::pick_relay_candidate`].
    friends: std::collections::HashSet<[u8; 16]>,
}

/// Events emitted by the broker for the main network loop to act on.
#[derive(Debug)]
pub enum BrokerEvent {
    /// Request relay from a peer or server.
    StartRelay {
        attempt_key: String,
        source_ip: Ipv4Addr,
        source_port: u16,
        /// The port the relay is to dial over QUIC.
        target_quic_port: u16,
        /// Set only when the chosen relay can pin to it.
        target_node_id: Option<[u8; 16]>,
        file_hash: [u8; 16],
        relay_addr: Option<(Ipv4Addr, u16)>,
        relay_attestation_hash: Option<[u8; 32]>,
        relay_ember_hash: Option<[u8; 16]>,
    },
    /// Hole-punch or relay succeeded -- connection ready for download.
    ConnectionReady(BrokerConnection),
    /// The source answered our eD2K Hello over the relay, which is what shows
    /// the relay works. ACCEPT alone does not: a 1.7.0 relay sends it before
    /// it has reached the source.
    ///
    /// `live` is answered with whether the attempt was still running, and only
    /// then may the greeted stream be handed to the download: an attempt that
    /// timed out has already been failed and its source moved on.
    RelayGreeted {
        attempt_key: String,
        live: tokio::sync::oneshot::Sender<bool>,
    },
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
        /// The relay declined to serve us (we are not its friend), so it is
        /// skipped for a while rather than charged; see
        /// [`ConnectionBroker::relay_refused_us`].
        refused_us: bool,
        /// The relay answered that it is at capacity, so it is skipped briefly;
        /// see [`ConnectionBroker::relay_was_busy`].
        relay_busy: bool,
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
            friend_hashes: None,
            friends: std::collections::HashSet::new(),
        }
    }

    /// Give the broker our friend list, which decides which relays can serve us.
    pub fn set_friend_hashes(&mut self, friend_hashes: crate::app_state::SharedFriendHashes) {
        self.friend_hashes = Some(friend_hashes);
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
        target: RelayTarget,
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

        if let Some(friend_hashes) = &self.friend_hashes {
            self.friends = friend_hashes.read().await.clone();
        }
        // Before the cooldown is charged: with no relay to ask, the attempt
        // could only fail, and it used to spend one of the source's
        // `MAX_ATTEMPTS_PER_SOURCE` tries doing so.
        if self.pick_relay_candidate().is_none() {
            debug!("Broker: no relay candidate for {source_ip}:{source_port}");
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
        let relay = relay_candidate.map(|c| (c.ip, c.port, c.attestation.ed25519_pubkey));
        let relay_pins = relay_candidate.is_some_and(|c| {
            c.attestation.capability_bits & super::RELAY_ATTESTATION_CAP_PINNED_TARGET != 0
        });
        let target_node_id = target.node_id.filter(|_| relay_pins);
        let target_quic_port = target.quic_port.unwrap_or(source_port);

        let attempt = ConnectionAttempt {
            transfer_id: transfer_id.to_string(),
            file_hash,
            source_ip,
            source_port,
            phase: start_phase,
            started: now,
            phase_started: now,
            relay,
            relay_attestation_hash,
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
                target_quic_port,
                target_node_id,
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
                if let Some((ip, port, pubkey)) = attempt.relay {
                    self.penalise_relay_candidate(ip, port, &pubkey);
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

    /// Called when the relay answered that it will not serve us. The attempt
    /// fails like any other, and the relay is skipped for
    /// [`RELAY_REFUSAL_BACKOFF`] without being counted as broken.
    ///
    /// A friend's relay refuses us only for an attestation it no longer
    /// honours, so its refusal is dropped when the candidate has since been
    /// refreshed with a different one: that is the attestation the next
    /// attempt presents. A stranger's is kept, since it refuses whatever we
    /// present.
    pub async fn relay_refused_us(&mut self, attempt_key: &str, reason: &str) {
        if let Some(attempt) = self.attempts.get(attempt_key) {
            let presented = attempt.relay_attestation_hash;
            let friends = &self.friends;
            if let Some(c) = attempt.relay.and_then(|relay| self.relay_candidates.iter_mut().find(|c| {
                c.ip == relay.0 && c.port == relay.1 && c.attestation.ed25519_pubkey == relay.2
            })) {
                let friend = c.ember_hash.is_some_and(|hash| friends.contains(&hash));
                if !friend || presented == Some(c.attestation_hash) {
                    c.refused_until = Some(Instant::now() + RELAY_REFUSAL_BACKOFF);
                }
            }
        }
        self.relay_failed(attempt_key, reason, false).await;
    }

    /// Called when the relay answered that it is at capacity. The attempt fails
    /// and the relay is skipped for [`RELAY_BUSY_BACKOFF`], blamed only when
    /// the answer could have come from someone else at its address.
    pub async fn relay_was_busy(&mut self, attempt_key: &str, reason: &str, relay_at_fault: bool) {
        if let Some(relay) = self.attempts.get(attempt_key).and_then(|a| a.relay) {
            if let Some(c) = self.relay_candidates.iter_mut().find(|c| {
                c.ip == relay.0 && c.port == relay.1 && c.attestation.ed25519_pubkey == relay.2
            }) {
                c.busy_until = Some(Instant::now() + RELAY_BUSY_BACKOFF);
            }
        }
        self.relay_failed(attempt_key, reason, relay_at_fault).await;
    }

    /// Time the attempt has left in its current phase, or `None` once it has
    /// ended.
    pub fn attempt_time_left(&self, attempt_key: &str) -> Option<Duration> {
        self.attempts.get(attempt_key).map(ConnectionAttempt::time_left)
    }

    /// Called when a relay succeeds. Returns whether the attempt was still
    /// live; a late success is not counted, and its stream must be dropped.
    pub fn mark_succeeded(&mut self, attempt_key: &str, _method: ConnectionMethod) -> bool {
        // An attempt already timed out was counted as a failure then.
        let Some(attempt) = self.attempts.remove(attempt_key) else {
            return false;
        };
        {
            if let Some((ip, port, pubkey)) = attempt.relay {
                // Clears the count rather than decrementing it: a relay that
                // just carried a connection has proved itself, and occasional
                // failures against a working relay should not accumulate into
                // an eviction.
                if let Some(c) = self
                    .relay_candidates
                    .iter_mut()
                    .find(|c| {
                        c.ip == ip
                            && c.port == port
                            && c.attestation.ed25519_pubkey == pubkey
                    })
                {
                    c.failures = 0;
                    c.refused_until = None;
                    c.busy_until = None;
                    c.relay_sessions += 1;
                    debug!(
                        "Broker: incremented relay_sessions for {}:{} to {}",
                        ip, port, c.relay_sessions
                    );
                }
            }
        }
        self.stats.relay_successes = self.stats.relay_successes.saturating_add(1);
        true
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
    fn penalise_relay_candidate(&mut self, ip: Ipv4Addr, port: u16, pubkey: &[u8; 32]) {
        let Some(idx) = self.relay_candidates.iter().position(|c| {
            c.ip == ip && c.port == port && c.attestation.ed25519_pubkey == *pubkey
        }) else {
            return;
        };
        self.relay_candidates[idx].failures = self.relay_candidates[idx].failures.saturating_add(1);
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
    /// admitted with (see `verify_relay_attestation` at the call site) —
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
        // Refresh only the same signer at this address. An ERAT does not
        // prove possession of the IP, so a different pubkey must not
        // overwrite identity, `failures`, or `introduced_by`.
        if let Some(existing) = self.relay_candidates.iter_mut().find(|c| {
            c.ip == ip
                && c.port == port
                && c.attestation.ed25519_pubkey == attestation.ed25519_pubkey
        }) {
            existing.last_seen = Instant::now();
            // Copies signed before the relay's latest keep circulating among
            // friends for their whole lifetime. Taking one back would shorten
            // the candidate's life, and could drop a capability bit the relay
            // has since gained or present an attestation a restarted relay no
            // longer honours.
            if expires_at_unix <= existing.expires_at_unix {
                return;
            }
            // A friend's relay never turns us away for not being its friend, so
            // its `REJECT_AUTH` meant an attestation it has rotated away from,
            // and a new one is worth trying. A stranger's is not cleared:
            // relays re-sign on every exchange, so clearing on any new hash
            // would undo the backoff within minutes.
            let friend = ember_hash.is_some_and(|hash| self.friends.contains(&hash));
            if friend && existing.attestation_hash != attestation_hash {
                existing.refused_until = None;
            }
            existing.attestation_hash = attestation_hash;
            existing.attestation = attestation;
            existing.ember_hash = ember_hash;
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
            refused_until: None,
            busy_until: None,
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

    /// Pick the best available relay candidate that is not already carrying
    /// [`MAX_ATTEMPTS_PER_RELAY`] of our attempts.
    ///
    /// A friend's relay first, because a relay carries only its friends'
    /// traffic, then fewest failures, then a relay that has carried a session
    /// before one that has not, then the most recently seen. Proven relays used
    /// to rank *behind* unused ones, on a lifetime session count that never
    /// went down, so one success sent a working friend relay behind every
    /// stranger's.
    ///
    /// Filters on both the age-based `RELAY_CANDIDATE_PICK_MAX_AGE` window
    /// *and* the candidate's own signed `expires_at_unix` — the age window
    /// alone is only an upper bound (aligned to the max ERAT TTL); a
    /// short-TTL attestation can expire well before it, and picking an
    /// already-expired candidate just wastes a relay attempt that the
    /// peer's own `accepts_attestation_hash` will reject anyway.
    fn pick_relay_candidate(&self) -> Option<&RelayCandidate> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let now = Instant::now();
        self.relay_candidates
            .iter()
            .filter(|c| {
                c.last_seen.elapsed() < RELAY_CANDIDATE_PICK_MAX_AGE
                    && c.expires_at_unix > now_unix
                    && c.refused_until.is_none_or(|until| until <= now)
                    && c.busy_until.is_none_or(|until| until <= now)
                    && self
                        .attempts
                        .values()
                        .filter(|a| a.relay.is_some_and(|(ip, port, _)| (ip, port) == (c.ip, c.port)))
                        .count()
                        < MAX_ATTEMPTS_PER_RELAY
            })
            // Failures rank ahead of everything but friendship. A candidate that
            // has just failed must not keep winning on "seen most recently",
            // which is how a fabricated entry used to outrank a relay that
            // demonstrably works.
            .min_by_key(|c| {
                let friend = c.ember_hash.is_some_and(|hash| self.friends.contains(&hash));
                (
                    !friend,
                    c.failures,
                    c.relay_sessions == 0,
                    c.last_seen.elapsed().as_secs(),
                )
            })
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
            let Some(phase) = self.attempts.get(&key).map(|a| a.phase) else {
                continue;
            };
            info!("Broker: relay timed out for {key} ({phase:?})");
            // The relay's account only once it had been asked: before that
            // no relay was involved, and after it connected us the silence is
            // the source's.
            self.relay_failed(&key, "timeout", phase == AttemptPhase::RelayConnect)
                .await;
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

    /// Transition an attempt to the RelayConnect phase.
    pub fn set_relay_phase(&mut self, attempt_key: &str) {
        self.set_phase(attempt_key, AttemptPhase::RelayConnect);
    }

    /// The relay delivered a stream; the source's Hello is next.
    pub fn set_greeting_phase(&mut self, attempt_key: &str) {
        self.set_phase(attempt_key, AttemptPhase::Greeting);
    }

    fn set_phase(&mut self, attempt_key: &str, phase: AttemptPhase) {
        if let Some(attempt) = self.attempts.get_mut(attempt_key) {
            attempt.phase = phase;
            attempt.phase_started = Instant::now();
        }
    }

    /// Whether the attempt is still live. A stream the relay delivers after the
    /// attempt timed out has already been counted as a failure, so it is
    /// dropped rather than also counted as a success.
    pub fn has_attempt(&self, attempt_key: &str) -> bool {
        self.attempts.contains_key(attempt_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A broker holding one usable relay candidate, which every attempt needs.
    fn broker_with_relay(tx: mpsc::Sender<BrokerEvent>) -> ConnectionBroker {
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        broker.add_relay_candidate(
            attestation(Ipv4Addr::new(1, 1, 1, 1), 4662, unix_now() + 600),
            None,
            None,
        );
        broker
    }

    #[tokio::test]
    async fn attempt_respects_cooldown() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut broker = broker_with_relay(tx);

        let started = broker
            .attempt_low_to_low(
                "t1",
                [1u8; 16],
                Ipv4Addr::new(1, 2, 3, 4),
                4662,
                RelayTarget::default(),
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
                RelayTarget::default(),
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
        let mut broker = broker_with_relay(tx);

        broker
            .attempt_low_to_low(
                "t2",
                [2u8; 16],
                Ipv4Addr::new(10, 20, 30, 40),
                4662,
                RelayTarget::default(),
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
        let mut broker = broker_with_relay(tx);

        broker
            .attempt_low_to_low(
                "t3",
                [3u8; 16],
                Ipv4Addr::new(10, 20, 30, 40),
                4662,
                RelayTarget::default(),
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
    /// `RELAY_CANDIDATE_PICK_MAX_AGE` window — the age window is only an
    /// upper bound (aligned to the max ERAT TTL), not a substitute for
    /// checking the attestation's own shorter-lived expiry.
    #[test]
    fn pick_relay_candidate_skips_expired_attestation() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);

        let expired = unix_now().saturating_sub(1);
        broker.add_relay_candidate(
            attestation(Ipv4Addr::new(9, 9, 9, 9), 4662, expired),
            None,
            None,
        );
        assert_eq!(broker.relay_candidate_count(), 1);
        assert!(broker.pick_relay_candidate().is_none());

        // A fresh, unexpired candidate is still pickable.
        let fresh = unix_now() + 600;
        broker.add_relay_candidate(
            attestation(Ipv4Addr::new(8, 8, 8, 8), 4662, fresh),
            None,
            None,
        );
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

        broker.add_relay_candidate(
            attestation(Ipv4Addr::new(1, 1, 1, 1), 4662, fresh),
            None,
            None,
        );
        broker.add_relay_candidate(
            attestation(Ipv4Addr::new(2, 2, 2, 2), 4663, stale),
            None,
            None,
        );

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
            broker.add_relay_candidate(
                attestation(Ipv4Addr::new(10, 0, 0, i), 4662, fresh),
                None,
                None,
            );
        }

        assert_eq!(
            broker.gossipable_attestations(now).len(),
            crate::network::ember::MAX_RELAY_ATTESTATIONS
        );
    }

    /// A relay serves only its friends, so a friend's relay wins over a
    /// stranger's however much better the stranger's looks otherwise, and a
    /// stranger that refused us is not asked again straight away, even when a
    /// re-signed attestation for it arrives.
    #[tokio::test]
    async fn a_friend_relay_that_worked_beats_strangers_who_refuse_us() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let fresh = unix_now() + 600;
        let friend_relay = Ipv4Addr::new(198, 51, 100, 20);
        let stranger = Ipv4Addr::new(198, 51, 100, 21);
        let friend_hash = [0xF1u8; 16];
        let friends: crate::app_state::SharedFriendHashes = Arc::new(tokio::sync::RwLock::new(
            std::collections::HashSet::from([friend_hash]),
        ));
        broker.set_friend_hashes(friends);

        // The stranger's relay looks better on every other count: proven, and
        // seen more recently.
        broker.add_relay_candidate(attestation(friend_relay, 4662, fresh), Some(friend_hash), None);
        if let Some(c) = broker.relay_candidates.iter_mut().find(|c| c.ip == friend_relay) {
            c.last_seen = Instant::now() - Duration::from_secs(5);
        }
        broker.add_relay_candidate(attestation(stranger, 4662, fresh), Some([0x55; 16]), None);
        if let Some(c) = broker.relay_candidates.iter_mut().find(|c| c.ip == stranger) {
            c.relay_sessions = 3;
        }

        assert!(
            broker
                .attempt_low_to_low("t1", [1; 16], Ipv4Addr::new(10, 0, 0, 1), 4662, RelayTarget::default(), NatType::Symmetric, None)
                .await
        );
        assert_eq!(broker.attempts["t1:10.0.0.1:4662"].relay.map(|r| r.0), Some(friend_relay));

        // Without the friend, the stranger is tried, refuses, and is skipped.
        broker.relay_candidates.retain(|c| c.ip != friend_relay);
        assert!(
            broker
                .attempt_low_to_low("t2", [2; 16], Ipv4Addr::new(10, 0, 0, 2), 4662, RelayTarget::default(), NatType::Symmetric, None)
                .await
        );
        broker.relay_refused_us("t2:10.0.0.2:4662", "not a friend").await;
        assert!(broker.pick_relay_candidate().is_none(), "a relay that refused us is skipped");
        broker.add_relay_candidate(attestation(stranger, 4662, fresh + 60), Some([0x55; 16]), None);
        assert!(
            broker.pick_relay_candidate().is_none(),
            "a re-signed attestation does not lift a stranger's refusal"
        );
        assert_eq!(
            broker.relay_candidates[0].failures, 0,
            "a refusal is a working relay's answer, not a failure"
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

        // Neither has carried traffic; the fabricated one was seen more
        // recently, which is exactly why it wins while its record is clean.
        broker.add_relay_candidate(attestation(working, 4662, fresh), None, None);
        if let Some(c) = broker.relay_candidates.iter_mut().find(|c| c.ip == working) {
            c.last_seen = Instant::now() - Duration::from_secs(5);
        }
        broker.add_relay_candidate(attestation(bogus, 4662, fresh), None, None);

        assert_eq!(
            broker.pick_relay_candidate().map(|c| c.ip),
            Some(bogus),
            "precondition: an unused candidate is preferred"
        );

        // One failure is enough to send it behind the relay that works.
        broker.penalise_relay_candidate(bogus, 4662, &[0u8; 32]);
        assert_eq!(
            broker.pick_relay_candidate().map(|c| c.ip),
            Some(working),
            "a failing candidate must not keep winning selection"
        );

        // And it is dropped rather than lingering to be retried for ever.
        for _ in 1..ConnectionBroker::MAX_CANDIDATE_FAILURES {
            broker.penalise_relay_candidate(bogus, 4662, &[0u8; 32]);
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
            broker
                .attempt_low_to_low(
                    "t-local",
                    [9u8; 16],
                    Ipv4Addr::new(10, 0, 0, 1),
                    4662,
                    RelayTarget::default(),
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
        broker.penalise_relay_candidate(ip, 4662, &[0u8; 32]);
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

    /// A forged ERAT for an honest relay's address is a *second* row, not a
    /// refresh. Failure must be charged to the signer we picked, or the
    /// honest row is burned toward eviction while the forged one stays at
    /// `failures: 0` and keeps winning the pick.
    #[tokio::test]
    async fn forged_attestation_at_an_honest_address_does_not_take_the_honest_failures() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let fresh = unix_now() + 600;
        let ip = Ipv4Addr::new(198, 51, 100, 9);
        let honest_pk = [1u8; 32];
        let forged_pk = [2u8; 32];

        let mut honest = attestation(ip, 4662, fresh);
        honest.ed25519_pubkey = honest_pk;
        broker.add_relay_candidate(honest, None, None);
        // `pick_relay_candidate` ranks `last_seen` in whole seconds, so two
        // inserts in the same second are a tie and the first (honest) row
        // wins. Age it so the forged row is selected the way a freshly
        // gossiped fabricated ERAT outranks a quiet relay on the live path.
        if let Some(c) = broker
            .relay_candidates
            .iter_mut()
            .find(|c| c.attestation.ed25519_pubkey == honest_pk)
        {
            c.last_seen = Instant::now() - Duration::from_secs(5);
        }

        let mut forged = attestation(ip, 4662, fresh);
        forged.ed25519_pubkey = forged_pk;
        broker.add_relay_candidate(forged, None, None);

        assert_eq!(broker.relay_candidate_count(), 2);
        assert_eq!(
            broker
                .pick_relay_candidate()
                .map(|c| c.attestation.ed25519_pubkey),
            Some(forged_pk),
            "precondition: the unused forged row wins the pick"
        );

        broker
            .attempt_low_to_low(
                "t-forge",
                [7u8; 16],
                Ipv4Addr::new(10, 0, 0, 2),
                4662,
                RelayTarget::default(),
                NatType::Symmetric,
                Some("5.6.7.8:9999".parse().unwrap()),
            )
            .await;
        broker
            .relay_failed("t-forge:10.0.0.2:4662", "handshake failed", true)
            .await;

        assert_eq!(
            broker
                .relay_candidates
                .iter()
                .find(|c| c.attestation.ed25519_pubkey == honest_pk)
                .map(|c| c.failures),
            Some(0)
        );
        assert_eq!(
            broker
                .relay_candidates
                .iter()
                .find(|c| c.attestation.ed25519_pubkey == forged_pk)
                .map(|c| c.failures),
            Some(1)
        );

        for _ in 1..ConnectionBroker::MAX_CANDIDATE_FAILURES {
            broker.penalise_relay_candidate(ip, 4662, &forged_pk);
        }
        assert!(
            broker
                .relay_candidates
                .iter()
                .any(|c| c.attestation.ed25519_pubkey == honest_pk),
            "the honest relay must survive the forged row's failures"
        );
        assert!(
            !broker
                .relay_candidates
                .iter()
                .any(|c| c.attestation.ed25519_pubkey == forged_pk),
            "the forged row must be the one evicted"
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
        broker.add_relay_candidate(
            attestation(Ipv4Addr::new(1, 1, 1, 1), 4662, fresh),
            None,
            None,
        );

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
        broker.add_relay_candidate(
            attestation(Ipv4Addr::new(1, 1, 1, 1), 4662, unix_now() + 600),
            None,
            None,
        );

        assert!(
            broker
                .attempt_low_to_low(
                    "t4",
                    [4u8; 16],
                    Ipv4Addr::new(10, 20, 30, 40),
                    4662,
                    RelayTarget::default(),
                    NatType::PortRestricted,
                    Some("5.6.7.8:9999".parse().unwrap()),
                )
                .await
        );

        assert!(matches!(
            rx.try_recv(),
            Ok(BrokerEvent::StartRelay { .. })
        ));
        assert!(rx.try_recv().is_err());
    }

    /// With no relay to ask, an attempt could only fail, so none starts and
    /// the source keeps its tries for when a relay is known.
    #[tokio::test]
    async fn no_relay_candidate_starts_no_attempt_and_spends_no_retry() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let source = Ipv4Addr::new(10, 20, 30, 43);
        for _ in 0..MAX_ATTEMPTS_PER_SOURCE + 1 {
            assert!(
                !broker
                    .attempt_low_to_low(
                        "t7",
                        [7u8; 16],
                        source,
                        4662,
                        RelayTarget::default(),
                        NatType::PortRestricted,
                        None,
                    )
                    .await
            );
        }
        assert!(rx.try_recv().is_err());
        assert!(!broker.cooldowns.contains_key(&(source, 4662)));

        broker.add_relay_candidate(
            attestation(Ipv4Addr::new(1, 1, 1, 1), 4662, unix_now() + 600),
            None,
            None,
        );
        assert!(
            broker
                .attempt_low_to_low(
                    "t7",
                    [7u8; 16],
                    source,
                    4662,
                    RelayTarget::default(),
                    NatType::PortRestricted,
                    None,
                )
                .await
        );
    }

    /// A timeout before the relay was asked, or while the source it connected
    /// us to is being greeted, is not the relay's failure; and a stream that
    /// arrives after the attempt was failed does not also count as a success.
    #[tokio::test]
    async fn timeouts_blame_the_relay_only_while_it_is_connecting_us() {
        let (tx, _rx) = mpsc::channel(64);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        broker.add_relay_candidate(
            attestation(Ipv4Addr::new(1, 1, 1, 1), 4662, unix_now() + 600),
            None,
            None,
        );
        let expire = |broker: &mut ConnectionBroker, key: &str| {
            let attempt = broker.attempts.get_mut(key).unwrap();
            attempt.phase_started = Instant::now() - RELAY_TIMEOUT - Duration::from_secs(1);
        };
        let start = |n: u8| (format!("t{n}"), Ipv4Addr::new(10, 0, 0, n));

        let (id, ip) = start(1);
        broker.attempt_low_to_low(&id, [1u8; 16], ip, 4662, RelayTarget::default(), NatType::PortRestricted, None).await;
        let key = format!("{id}:{ip}:4662");
        broker.set_relay_phase(&key);
        broker.set_greeting_phase(&key);
        expire(&mut broker, &key);
        broker.tick().await;
        assert_eq!(broker.relay_candidates[0].failures, 0, "the source went quiet, not the relay");

        let (id, ip) = start(2);
        broker.attempt_low_to_low(&id, [2u8; 16], ip, 4662, RelayTarget::default(), NatType::PortRestricted, None).await;
        let key = format!("{id}:{ip}:4662");
        broker.set_relay_phase(&key);
        expire(&mut broker, &key);
        broker.tick().await;
        assert_eq!(broker.relay_candidates[0].failures, 1, "the relay did not answer in time");
        assert!(!broker.has_attempt(&key));

        let successes = broker.stats().relay_successes;
        broker.mark_succeeded(&key, ConnectionMethod::PeerRelay);
        assert_eq!(broker.stats().relay_successes, successes, "a late success is not counted");
    }

    fn friends(hashes: &[[u8; 16]]) -> crate::app_state::SharedFriendHashes {
        Arc::new(tokio::sync::RwLock::new(hashes.iter().copied().collect()))
    }

    /// Answers the next `RelayGreeted` the way the network loop does, skipping
    /// the `ConnectionFailed` a timed-out attempt emits first.
    async fn answer_greeting(broker: &mut ConnectionBroker, rx: &mut mpsc::Receiver<BrokerEvent>) {
        loop {
            match rx.recv().await {
                Some(BrokerEvent::RelayGreeted { attempt_key, live }) => {
                    let _ = live.send(broker.mark_succeeded(&attempt_key, ConnectionMethod::PeerRelay));
                    return;
                }
                Some(_) => continue,
                None => panic!("broker channel closed"),
            }
        }
    }

    /// A Hello that answers while its attempt is live hands the stream over and
    /// counts the success; one that answers after the attempt timed out, and
    /// was failed, hands nothing over and counts nothing.
    #[tokio::test]
    async fn a_greeted_stream_goes_to_the_download_only_while_its_attempt_is_live() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut broker = broker_with_relay(tx.clone());
        let source = Ipv4Addr::new(10, 0, 0, 1);
        assert!(broker.attempt_low_to_low("t1", [1; 16], source, 4662, RelayTarget::default(), NatType::Symmetric, None).await);
        let key = "t1:10.0.0.1:4662".to_string();
        assert!(matches!(rx.recv().await, Some(BrokerEvent::StartRelay { .. })));
        broker.set_relay_phase(&key);
        broker.set_greeting_phase(&key);

        let time_left = broker.attempt_time_left(&key).unwrap();
        assert!(time_left > RELAY_TIMEOUT - Duration::from_secs(1));
        let greeting = tokio::spawn({
            let (key, tx) = (key.clone(), tx.clone());
            async move { greet_within_attempt(async { Ok(7u8) }, time_left, key, &tx).await }
        });
        answer_greeting(&mut broker, &mut rx).await;
        assert_eq!(greeting.await.unwrap(), Some(7));
        assert_eq!(broker.stats().relay_successes, 1);

        broker.cooldowns.clear();
        assert!(broker.attempt_low_to_low("t1", [1; 16], source, 4662, RelayTarget::default(), NatType::Symmetric, None).await);
        broker.set_greeting_phase(&key);
        let (answered_tx, answered_rx) = tokio::sync::oneshot::channel::<()>();
        let greeting = tokio::spawn({
            let (key, tx) = (key.clone(), tx.clone());
            async move {
                let hello = async {
                    let _ = answered_rx.await;
                    Ok(7u8)
                };
                greet_within_attempt(hello, RELAY_TIMEOUT, key, &tx).await
            }
        });
        broker.attempts.get_mut(&key).unwrap().phase_started =
            Instant::now() - RELAY_TIMEOUT - Duration::from_secs(1);
        broker.tick().await;
        assert!(!broker.has_attempt(&key));
        answered_tx.send(()).unwrap();
        answer_greeting(&mut broker, &mut rx).await;
        assert_eq!(greeting.await.unwrap(), None, "a late stream is dropped");
        assert_eq!(broker.stats().relay_successes, 1, "and not counted");
    }

    /// The Hello is bounded by what is left of its attempt, and a silent source
    /// fails the attempt through the loop rather than holding the stream.
    #[tokio::test]
    async fn a_hello_that_never_answers_is_bounded_by_its_attempt() {
        let (tx, mut rx) = mpsc::channel(16);
        let greeted = greet_within_attempt(
            std::future::pending::<anyhow::Result<()>>(),
            Duration::from_millis(50),
            "t1:10.0.0.1:4662".into(),
            &tx,
        )
        .await;
        assert!(greeted.is_none());
        assert!(matches!(
            rx.try_recv(),
            Ok(BrokerEvent::RelayFailed { relay_at_fault: false, refused_us: false, relay_busy: false, .. })
        ));
    }

    /// A full event queue delays the report of a working connection rather
    /// than losing it, which would leave the attempt to be failed by the
    /// timeout.
    #[tokio::test]
    async fn a_greeting_report_waits_for_room_in_the_event_queue() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(BrokerEvent::RelayFailed {
            attempt_key: "filler".into(),
            reason: String::new(),
            relay_at_fault: false,
            refused_us: false,
            relay_busy: false,
        })
        .unwrap();
        let greeting = tokio::spawn({
            let tx = tx.clone();
            async move { greet_within_attempt(async { Ok(()) }, RELAY_TIMEOUT, "t1".into(), &tx).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(matches!(rx.recv().await, Some(BrokerEvent::RelayFailed { .. })));
        match rx.recv().await {
            Some(BrokerEvent::RelayGreeted { live, .. }) => live.send(true).unwrap(),
            other => panic!("expected RelayGreeted, got {other:?}"),
        }
        assert_eq!(greeting.await.unwrap(), Some(()));
    }

    /// A relay at capacity is passed over for a minute, not blamed, and not
    /// asked for the next source in the meantime, which would only spend that
    /// source's attempt on the same refusal. A refused handshake, which anyone
    /// at the address could send, is passed over the same way but charged.
    #[tokio::test]
    async fn a_busy_relay_is_skipped_briefly_without_blame() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let friend_hash = [0xF1u8; 16];
        broker.set_friend_hashes(friends(&[friend_hash]));
        let relay = Ipv4Addr::new(198, 51, 100, 30);
        broker.add_relay_candidate(attestation(relay, 4662, unix_now() + 600), Some(friend_hash), None);

        assert!(broker.attempt_low_to_low("t1", [1; 16], Ipv4Addr::new(10, 0, 0, 1), 4662, RelayTarget::default(), NatType::Symmetric, None).await);
        broker.relay_was_busy("t1:10.0.0.1:4662", "at capacity", false).await;
        assert!(broker.pick_relay_candidate().is_none(), "a busy relay is skipped");
        assert_eq!(broker.relay_candidates[0].failures, 0, "being busy is not failing");
        let next = Ipv4Addr::new(10, 0, 0, 2);
        assert!(
            !broker.attempt_low_to_low("t2", [2; 16], next, 4662, RelayTarget::default(), NatType::Symmetric, None).await,
            "no attempt is spent on a relay known to be full"
        );
        assert!(!broker.cooldowns.contains_key(&(next, 4662)));

        let busy_until = broker.relay_candidates[0].busy_until.unwrap();
        assert!(busy_until <= Instant::now() + RELAY_BUSY_BACKOFF);
        assert!(busy_until > Instant::now() + RELAY_BUSY_BACKOFF - Duration::from_secs(5));
        broker.relay_candidates[0].busy_until = Some(Instant::now());
        assert_eq!(broker.pick_relay_candidate().map(|c| c.ip), Some(relay), "and tried again after");

        assert!(broker.attempt_low_to_low("t3", [3; 16], Ipv4Addr::new(10, 0, 0, 3), 4662, RelayTarget::default(), NatType::Symmetric, None).await);
        broker.relay_was_busy("t3:10.0.0.3:4662", "handshake refused", true).await;
        assert!(broker.pick_relay_candidate().is_none(), "a refused handshake is skipped too");
        assert_eq!(broker.relay_candidates[0].failures, 1, "and counted against the relay");
    }

    /// One pass over a swarm's firewalled sources starts several attempts at
    /// once. A relay is asked for no more of them than it holds sessions for
    /// one requester; the rest go to the next relay, or wait without spending
    /// a try when there is none, and a slot frees when an attempt ends.
    #[tokio::test]
    async fn a_relay_is_given_no_more_attempts_than_it_holds_for_us() {
        let (tx, _rx) = mpsc::channel(64);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let friend_hash = [0xF1u8; 16];
        broker.set_friend_hashes(friends(&[friend_hash]));
        let friend_relay = Ipv4Addr::new(198, 51, 100, 50);
        let other_relay = Ipv4Addr::new(198, 51, 100, 51);
        broker.add_relay_candidate(attestation(friend_relay, 4662, unix_now() + 600), Some(friend_hash), None);
        let source = |n: u8| Ipv4Addr::new(10, 0, 0, n);
        async fn start(broker: &mut ConnectionBroker, n: u8) -> bool {
            let source = Ipv4Addr::new(10, 0, 0, n);
            broker
                .attempt_low_to_low(&format!("t{n}"), [n; 16], source, 4662, RelayTarget::default(), NatType::Symmetric, None)
                .await
        }
        let relay_of = |broker: &ConnectionBroker, n: u8| {
            broker.attempts[&format!("t{n}:{}:4662", source(n))].relay.map(|r| r.0)
        };

        for n in 1..=MAX_ATTEMPTS_PER_RELAY as u8 {
            assert!(start(&mut broker, n).await);
            assert_eq!(relay_of(&broker, n), Some(friend_relay));
        }
        let spill = MAX_ATTEMPTS_PER_RELAY as u8 + 1;
        assert!(!start(&mut broker, spill).await, "a full relay is not asked again");
        assert!(!broker.cooldowns.contains_key(&(source(spill), 4662)));

        broker.add_relay_candidate(attestation(other_relay, 4662, unix_now() + 600), None, None);
        assert!(start(&mut broker, spill).await);
        assert_eq!(relay_of(&broker, spill), Some(other_relay), "the next relay takes it");

        broker.relay_failed("t1:10.0.0.1:4662", "source gone", false).await;
        let after = spill + 1;
        assert!(start(&mut broker, after).await);
        assert_eq!(relay_of(&broker, after), Some(friend_relay), "an ended attempt frees its slot");
    }

    /// Copies of a relay's attestation signed before its latest keep arriving
    /// from friends that still hold them. One of those must not replace the
    /// newer copy: it would shorten the candidate's life and could drop the
    /// relay's pinning bit.
    #[test]
    fn an_older_copy_of_an_attestation_does_not_replace_a_newer_one() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let ip = Ipv4Addr::new(198, 51, 100, 60);
        let fresh = unix_now() + 600;
        let mut newer = attestation(ip, 4662, fresh + 60);
        newer.capability_bits |= crate::network::ember::RELAY_ATTESTATION_CAP_PINNED_TARGET;
        let older = attestation(ip, 4662, fresh);

        broker.add_relay_candidate(newer.clone(), None, None);
        broker.relay_candidates[0].last_seen = Instant::now() - Duration::from_secs(300);
        broker.add_relay_candidate(older, None, None);

        let stored = &broker.relay_candidates[0];
        assert_eq!(broker.relay_candidate_count(), 1);
        assert_eq!(stored.attestation, newer);
        assert_eq!(stored.expires_at_unix, fresh + 60);
        assert_eq!(stored.attestation_hash, crate::network::ember::relay_attestation_hash(&newer));
        assert!(stored.last_seen.elapsed() < Duration::from_secs(5), "seeing it still counts");
    }

    /// A friend's `REJECT_AUTH` answers the attestation the attempt presented.
    /// When the candidate has been refreshed with another since, the refusal
    /// says nothing about the one the next attempt will present, so it does not
    /// bench the relay for an hour; a stranger's refusal does, either way.
    #[tokio::test]
    async fn a_refusal_of_a_superseded_friend_attestation_does_not_bench_the_relay() {
        let (tx, _rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        let friend_hash = [0xF1u8; 16];
        let stranger_hash = [0x55u8; 16];
        broker.set_friend_hashes(friends(&[friend_hash]));
        let fresh = unix_now() + 600;
        let relay = Ipv4Addr::new(198, 51, 100, 40);
        let source = |n: u8| Ipv4Addr::new(10, 0, 0, n);
        let attempt = |n: u8| format!("t{n}:{}:4662", source(n));

        for (n, hash) in [(1u8, friend_hash), (2, stranger_hash)] {
            broker.relay_candidates.clear();
            broker.add_relay_candidate(attestation(relay, 4662, fresh), Some(hash), None);
            assert!(broker.attempt_low_to_low(&format!("t{n}"), [n; 16], source(n), 4662, RelayTarget::default(), NatType::Symmetric, None).await);
            broker.add_relay_candidate(attestation(relay, 4662, fresh + 60), Some(hash), None);
            broker.relay_refused_us(&attempt(n), "not a friend").await;
            let benched = broker.relay_candidates[0].refused_until.is_some();
            assert_eq!(benched, hash == stranger_hash, "friend={}", hash == friend_hash);
        }

        broker.relay_candidates.clear();
        broker.add_relay_candidate(attestation(relay, 4662, fresh), Some(friend_hash), None);
        assert!(broker.attempt_low_to_low("t3", [3; 16], source(3), 4662, RelayTarget::default(), NatType::Symmetric, None).await);
        broker.relay_refused_us(&attempt(3), "unknown attestation").await;
        assert!(
            broker.relay_candidates[0].refused_until.is_some(),
            "a friend refusing the attestation it still holds is benched"
        );
    }

    /// The relay is told the source's QUIC port whenever it is known, and the
    /// source's node id only when the relay says it can pin to one, since a
    /// relay that cannot refuses the longer request outright.
    #[tokio::test]
    async fn the_target_id_goes_only_to_a_relay_that_pins() {
        let source = RelayTarget {
            quic_port: Some(5001),
            node_id: Some([9u8; 16]),
        };
        for (caps, expect_id) in [
            (crate::network::ember::RELAY_ATTESTATION_CAP_RELAY_V1, None),
            (
                crate::network::ember::RELAY_ATTESTATION_CAP_RELAY_V1
                    | crate::network::ember::RELAY_ATTESTATION_CAP_PINNED_TARGET,
                Some([9u8; 16]),
            ),
        ] {
            let (tx, mut rx) = mpsc::channel(16);
            let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
            let mut relay = attestation(Ipv4Addr::new(1, 1, 1, 1), 4662, unix_now() + 600);
            relay.capability_bits = caps;
            broker.add_relay_candidate(relay, None, None);
            broker
                .attempt_low_to_low(
                    "t5",
                    [5u8; 16],
                    Ipv4Addr::new(10, 20, 30, 41),
                    4662,
                    source,
                    NatType::PortRestricted,
                    None,
                )
                .await;
            match rx.recv().await {
                Some(BrokerEvent::StartRelay {
                    target_quic_port,
                    target_node_id,
                    relay_addr,
                    ..
                }) => {
                    assert!(relay_addr.is_some());
                    assert_eq!(target_quic_port, 5001);
                    assert_eq!(target_node_id, expect_id);
                }
                other => panic!("expected StartRelay, got {other:?}"),
            }
        }

        let (tx, mut rx) = mpsc::channel(16);
        let mut broker = ConnectionBroker::new("http://localhost".into(), tx);
        broker.add_relay_candidate(
            attestation(Ipv4Addr::new(1, 1, 1, 1), 4662, unix_now() + 600),
            None,
            None,
        );
        broker
            .attempt_low_to_low(
                "t6",
                [6u8; 16],
                Ipv4Addr::new(10, 20, 30, 42),
                4662,
                RelayTarget::default(),
                NatType::PortRestricted,
                None,
            )
            .await;
        assert!(matches!(
            rx.try_recv(),
            Ok(BrokerEvent::StartRelay { target_quic_port: 4662, target_node_id: None, .. })
        ));
    }
}
