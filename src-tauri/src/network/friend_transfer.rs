//! Friend-to-friend transfer negotiation: connect-back and coordinated
//! punch requests, callbacks, and their outcomes.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// How long a friend has to complete the connect-back we asked for with
/// `OP_EMBER_XFER_REQ` before the source is released back to ordinary retry.
/// Generous relative to a TCP dial because the friend must notice the request
/// on its session, dial us, and finish a Noise IK plus eD2K handshake.
pub(super) const FRIEND_XFER_ATTEMPT_TIMEOUT_SECS: u64 = 60;
/// Minimum gap between `OP_EMBER_XFER_REQ`s for the same `(friend, file)`.
/// Mirrors the broker's `ATTEMPT_COOLDOWN` so a friend who is offline or
/// declining doesn't get hammered once per source-retry round.
pub(super) const FRIEND_XFER_COOLDOWN_SECS: u64 = 120;
/// Requests for one `(friend, file)` before we stop asking and let the source
/// fall back to the ordinary dead-source path.
pub(super) const FRIEND_XFER_MAX_ATTEMPTS: u32 = 3;
/// How long accepting a `Punch` request keeps the punch responder armed to take
/// the eD2K serve role for that friend.
///
/// Comfortably longer than the rendezvous server's 30 s punch TTL so a punch we
/// agreed to can still be served, but short enough that a later *social* punch
/// from the same friend is not mistaken for the transfer — that would leave both
/// sides waiting on each other's `OP_HELLO`.
pub(super) const FRIEND_XFER_PUNCH_SERVE_TTL_SECS: u64 = 45;

/// Session counters for friend-to-friend transfer negotiation, mirroring
/// [`ember::broker::BrokerStats`] for the LowID broker.
///
/// These matter more than usual here: neither a connect-back nor a coordinated
/// punch can be exercised by a unit test — both depend on real NAT behaviour —
/// so in the field these counters are the only way to tell whether the
/// mechanism is actually working or silently never firing.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct FriendXferStats {
    /// `OP_EMBER_XFER_REQ`s we sent asking a friend to dial us.
    pub(super) connect_back_requested: u32,
    /// `OP_EMBER_XFER_REQ`s we sent asking for a coordinated hole-punch.
    pub(super) punch_requested: u32,
    /// Requests a friend accepted.
    pub(super) accepted: u32,
    /// Requests a friend declined, for any reason.
    pub(super) declined: u32,
    /// Friend connections that were adopted into a waiting download — the only
    /// counter that proves an end-to-end success.
    pub(super) connected: u32,
    /// Requests that never produced a connection before the attempt timeout.
    pub(super) timed_out: u32,
    /// Inbound requests we accepted, committing us to reach the friend.
    pub(super) inbound_accepted: u32,
    /// Inbound requests we declined.
    pub(super) inbound_declined: u32,
}

/// An `OP_EMBER_XFER_REQ` we sent and are waiting on.
#[derive(Debug, Clone)]
pub(super) struct FriendXferAttempt {
    /// The download this request was made for, so a matching connect-back can
    /// be attributed and the UI row updated.
    pub(super) transfer_id: String,
    /// Echoed back in `OP_EMBER_XFER_ACK`. An ack carrying any other nonce is
    /// from a superseded attempt and is ignored.
    pub(super) nonce: [u8; 16],
    /// How we asked the friend to reach us. Needed on the ack path, where a
    /// `Punch` acceptance is what triggers our rendezvous registration, and by
    /// the punch poll's adaptive gate.
    pub(super) transport: FriendXferTransport,
    /// When the most recent request went out, driving both the attempt
    /// timeout and the per-`(friend, file)` cooldown.
    pub(super) sent_at: std::time::Instant,
    pub(super) attempts: u32,
    /// Set by the first accept for this nonce. A friend may repeat its ack,
    /// and each repeat must not publish another punch registration.
    pub(super) accepted: bool,
}

/// Why [`friend_xfer_send_decision`] allowed or refused an
/// `OP_EMBER_XFER_REQ`. Split out from [`request_friend_transfer`] so the
/// rate-limiting and serialization rules — which the connect-back matching in
/// `upload.rs` depends on for correctness — are testable without a live
/// `NetworkState`, friend session, or socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FriendXferSendDecision {
    /// Send the request; this is attempt number `previous_attempts + 1`.
    Send { previous_attempts: u32 },
    /// Neither a connect-back nor a hole-punch is possible right now — see
    /// [`friend_xfer_transport_choice`].
    NoUsableTransport,
    /// This `(friend, file)` was asked too recently.
    Cooldown,
    /// This `(friend, file)` is out of attempts.
    Exhausted,
    /// A request to this friend for a *different* file is still in flight.
    AnotherOutstanding,
}

/// How we want a friend to reach us for a transfer, and the port that method
/// needs. Chosen by [`friend_xfer_transport_choice`] from our own reachability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FriendXferTransport {
    /// We are dialable: ask the friend to connect to our TCP listener.
    ConnectBack { tcp_port: u16 },
    /// Neither of us is dialable: coordinate a QUIC hole-punch on this port.
    Punch { quic_port: u16 },
}

impl FriendXferTransport {
    pub(super) fn method(self) -> ed2k::messages::EmberXferMethod {
        match self {
            Self::ConnectBack { .. } => ed2k::messages::EmberXferMethod::ConnectBack,
            Self::Punch { .. } => ed2k::messages::EmberXferMethod::Punch,
        }
    }

    /// The value to put in [`ed2k::messages::EmberXferRequest::tcp_port`].
    /// Punch carries no port on the wire — the friend reads our address from
    /// its rendezvous punch mailbox — so it sends `0`.
    pub(super) fn wire_port(self) -> u16 {
        match self {
            Self::ConnectBack { tcp_port } => tcp_port,
            Self::Punch { .. } => 0,
        }
    }
}

/// Pick how to ask a friend to reach us, preferring the cheaper method.
///
/// A connect-back wins whenever we are dialable: it costs one TCP dial with no
/// rendezvous round trip and no timing window. Only when we are firewalled too
/// do we fall back to a coordinated punch, which additionally requires a bound
/// QUIC endpoint, a known external address, an active rendezvous registration,
/// and a NAT that isn't symmetric — a symmetric NAT re-maps per destination, so
/// the port we register is not the port the friend would arrive on.
///
/// An `Err` means we cannot be reached by any method we support, which with
/// relay deliberately excluded is a dead end for the pair. The reason is
/// carried because only one of them is worth telling the user about: see
/// [`NoTransportReason::is_permanent`].
pub(super) fn friend_xfer_transport_choice(
    firewalled: bool,
    advertised_tcp_port: u16,
    quic_port: Option<u16>,
    nat_type: ember::nat::NatType,
    external_addr: Option<SocketAddr>,
    rendezvous_registered: bool,
) -> Result<FriendXferTransport, NoTransportReason> {
    if !firewalled && advertised_tcp_port != 0 {
        return Ok(FriendXferTransport::ConnectBack {
            tcp_port: advertised_tcp_port,
        });
    }

    // Checked ahead of the transient preconditions so the reported reason is
    // stable: a symmetric NAT that is also still waiting on its QUIC bind must
    // not report the transient cause and then flip to the permanent one a
    // moment later, which would let a startup race decide what the user reads.
    if nat_type == ember::nat::NatType::Symmetric {
        return Err(NoTransportReason::SymmetricNat);
    }
    let Some(quic_port) = quic_port.filter(|p| *p != 0) else {
        return Err(NoTransportReason::NoQuicPort);
    };
    if external_addr.is_none() {
        return Err(NoTransportReason::NoExternalAddr);
    }
    if !rendezvous_registered {
        return Err(NoTransportReason::NotRegistered);
    }
    Ok(FriendXferTransport::Punch { quic_port })
}

/// Why [`friend_xfer_transport_choice`] could offer the friend no way to reach
/// us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NoTransportReason {
    /// A symmetric NAT re-maps per destination, so the port we register is not
    /// the port the friend would arrive on. Nothing we do at runtime changes
    /// this; the user has to forward a port.
    SymmetricNat,
    /// No QUIC endpoint bound yet.
    NoQuicPort,
    /// STUN has not told us our external address yet.
    NoExternalAddr,
    /// Not registered at the rendezvous, so the friend's mailbox poll would
    /// find nothing.
    NotRegistered,
}

impl NoTransportReason {
    /// Whether this will still be true however long we wait. The three
    /// transient reasons all resolve on their own during startup, so surfacing
    /// them would only teach users to ignore the warning.
    pub(super) fn is_permanent(self) -> bool {
        matches!(self, NoTransportReason::SymmetricNat)
    }
}

/// Pure half of [`request_friend_transfer`]: decide whether to ask `friend` for
/// `file_hash`, given whether any transport is usable and the requests already
/// in flight.
pub(super) fn friend_xfer_send_decision(
    transport_available: bool,
    attempts: &HashMap<([u8; 16], [u8; 16]), FriendXferAttempt>,
    friend: [u8; 16],
    file_hash: [u8; 16],
    now: std::time::Instant,
) -> FriendXferSendDecision {
    if !transport_available {
        return FriendXferSendDecision::NoUsableTransport;
    }

    let previous_attempts = match attempts.get(&(friend, file_hash)) {
        Some(existing) => {
            if now.saturating_duration_since(existing.sent_at).as_secs() < FRIEND_XFER_COOLDOWN_SECS
            {
                return FriendXferSendDecision::Cooldown;
            }
            if existing.attempts >= FRIEND_XFER_MAX_ATTEMPTS {
                return FriendXferSendDecision::Exhausted;
            }
            existing.attempts
        }
        None => 0,
    };

    // At most one outstanding request per friend. Their connect-back carries no
    // per-request marker of its own — the inbound diversion identifies it by
    // Ember hash — so two live requests to the same friend would make the
    // arriving connection ambiguous between two files. Serializing them keeps
    // the match exact; the second file escalates on its next failed dial.
    let another_outstanding = attempts.iter().any(|(k, attempt)| {
        k.0 == friend
            && k.1 != file_hash
            && now.saturating_duration_since(attempt.sent_at).as_secs()
                < FRIEND_XFER_ATTEMPT_TIMEOUT_SECS
    });
    if another_outstanding {
        return FriendXferSendDecision::AnotherOutstanding;
    }

    FriendXferSendDecision::Send { previous_attempts }
}

/// The outstanding request `nonce` answers, if any. An ack whose nonce matches
/// no live attempt for `friend` is from a superseded or replayed attempt.
pub(super) fn find_friend_xfer_attempt(
    attempts: &HashMap<([u8; 16], [u8; 16]), FriendXferAttempt>,
    friend: [u8; 16],
    nonce: [u8; 16],
) -> Option<([u8; 16], [u8; 16])> {
    attempts
        .iter()
        .find(|((eh, _), attempt)| *eh == friend && attempt.nonce == nonce)
        .map(|(key, _)| *key)
}

/// Ask `friend` over their live friend session to reach us for `file_hash`
/// (`OP_EMBER_XFER_REQ`), the friend-layer stand-in for an eD2K server
/// callback. Returns whether a request actually went out.
///
/// Declines to ask — returning `false` so the caller falls through to the
/// ordinary dead-source handling — when:
/// * neither a connect-back nor a punch is possible (see
///   [`friend_xfer_transport_choice`]);
/// * no fresh secure friend session exists to carry the request;
/// * this `(friend, file)` is inside its cooldown or out of attempts.
///
/// The pending inbound expectation is registered *before* the request is sent
/// rather than when the ack arrives: the friend may complete its dial while
/// their ack is still in flight, and an unrecognised connect-back would be
/// served as an ordinary upload instead of feeding the download.
///
/// For [`FriendXferTransport::Punch`] this only sends the request; the
/// rendezvous punch registration waits until the friend accepts (see
/// [`handle_friend_transfer_ack`]) so the registration never exists while the
/// friend is still unaware it belongs to a transfer.
pub(super) async fn request_friend_transfer(
    state: &mut NetworkState,
    pending: &upload_server::PendingKadCallbacks,
    transfer_id: &str,
    friend: [u8; 16],
    file_hash: [u8; 16],
) -> FriendXferRequestOutcome {
    let now = std::time::Instant::now();
    let key = (friend, file_hash);
    let transport = friend_xfer_transport_choice(
        state.firewalled,
        advertised_tcp_port(state),
        advertised_quic_port(state),
        state.nat_info.nat_type,
        state.nat_info.external_addr,
        state.rendezvous_registered,
    );
    let (transport, previous_attempts) =
        match friend_xfer_request_plan(transport, &state.friend_xfer_attempts, key, now) {
            Ok(plan) => plan,
            Err(outcome) => return outcome,
        };

    let session = state
        .ember_sessions
        .read()
        .await
        .get(&friend)
        .filter(|handle| handle.is_fresh() && handle.is_secure_v2())
        .cloned();
    let Some(session) = session else {
        debug!(
            "No live secure session with friend {} to request a transfer on",
            hex::encode(friend)
        );
        return FriendXferRequestOutcome::Refused;
    };

    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let request = ed2k::messages::EmberXferRequest {
        method: transport.method(),
        file_hash,
        tcp_port: transport.wire_port(),
        nonce,
    };
    let payload = ed2k::messages::build_ember_xfer_req(&request);
    let mut packet = Vec::with_capacity(6 + payload.len());
    packet.push(OP_EMULEPROT);
    packet.extend_from_slice(&((1 + payload.len()) as u32).to_le_bytes());
    packet.push(ed2k::messages::OP_EMBER_XFER_REQ);
    packet.extend_from_slice(&payload);
    if let Err(e) = session.tx.try_send(packet) {
        debug!(
            "Could not queue transfer request to friend {}: {e}",
            hex::encode(friend)
        );
        return FriendXferRequestOutcome::Refused;
    }

    register_or_refresh_pending_friend_callback(pending, friend, file_hash).await;
    record_friend_xfer_request(
        &mut state.friend_xfer_attempts,
        &mut state.friend_xfer_stats,
        key,
        FriendXferAttempt {
            transfer_id: transfer_id.to_string(),
            nonce,
            sent_at: now,
            attempts: previous_attempts + 1,
            transport,
            accepted: false,
        },
    );
    info!(
        "Asked friend {} to reach us via {:?} for {} (attempt {})",
        hex::encode(friend),
        transport,
        hex::encode(file_hash),
        previous_attempts + 1
    );
    FriendXferRequestOutcome::Sent
}

/// What [`request_friend_transfer`] did. `NoTransport` is separated from the
/// ordinary refusals (cooldown, no session, already outstanding) because it is
/// the only one the user can act on, and the only one that parks the source as
/// [`ed2k::sources::DownloadSourceState::Unreachable`] rather than letting it
/// be swept away as a plain failure.
///
/// `Outstanding` is the refusal that only means "not yet": a request to this
/// friend, for this file or another, is still in flight, and one per friend
/// is all we send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FriendXferRequestOutcome {
    Sent,
    Outstanding,
    Refused,
    NoTransport(NoTransportReason),
}

/// Whether `refused` was for want of an answer to a request still in flight.
fn friend_xfer_request_in_flight(
    refused: FriendXferSendDecision,
    attempts: &HashMap<([u8; 16], [u8; 16]), FriendXferAttempt>,
    key: ([u8; 16], [u8; 16]),
    now: std::time::Instant,
) -> bool {
    match refused {
        FriendXferSendDecision::AnotherOutstanding => true,
        FriendXferSendDecision::Cooldown => attempts.get(&key).is_some_and(|attempt| {
            now.saturating_duration_since(attempt.sent_at).as_secs()
                < FRIEND_XFER_ATTEMPT_TIMEOUT_SECS
        }),
        _ => false,
    }
}

/// Pure half of [`request_friend_transfer`] up to the session lookup: the
/// transport to ask with and the attempts already made, or the outcome that
/// stops the request before anything is sent.
fn friend_xfer_request_plan(
    transport: Result<FriendXferTransport, NoTransportReason>,
    attempts: &HashMap<([u8; 16], [u8; 16]), FriendXferAttempt>,
    key: ([u8; 16], [u8; 16]),
    now: std::time::Instant,
) -> Result<(FriendXferTransport, u32), FriendXferRequestOutcome> {
    let (friend, file_hash) = key;
    let previous_attempts =
        match friend_xfer_send_decision(transport.is_ok(), attempts, friend, file_hash, now) {
            FriendXferSendDecision::Send { previous_attempts } => previous_attempts,
            refused => {
                debug!(
                    "Not asking friend {} to reach us for {}: {refused:?}",
                    hex::encode(friend),
                    hex::encode(file_hash)
                );
                if friend_xfer_request_in_flight(refused, attempts, key, now) {
                    return Err(FriendXferRequestOutcome::Outstanding);
                }
                return Err(match transport {
                    Err(reason) if reason.is_permanent() => {
                        FriendXferRequestOutcome::NoTransport(reason)
                    }
                    _ => FriendXferRequestOutcome::Refused,
                });
            }
        };
    let Ok(transport) = transport else {
        return Err(FriendXferRequestOutcome::Refused);
    };
    Ok((transport, previous_attempts))
}

/// Bookkeeping for a request that went out: it becomes the attempt in flight
/// for `key`, and counts towards its method's stat.
fn record_friend_xfer_request(
    attempts: &mut HashMap<([u8; 16], [u8; 16]), FriendXferAttempt>,
    stats: &mut FriendXferStats,
    key: ([u8; 16], [u8; 16]),
    attempt: FriendXferAttempt,
) {
    match attempt.transport {
        FriendXferTransport::ConnectBack { .. } => {
            stats.connect_back_requested = stats.connect_back_requested.saturating_add(1)
        }
        FriendXferTransport::Punch { .. } => {
            stats.punch_requested = stats.punch_requested.saturating_add(1)
        }
    }
    attempts.insert(key, attempt);
}

/// Register (or refresh) the expectation that `friend` will dial us for
/// `file_hash`, so the upload listener diverts their connection into the
/// waiting download instead of serving it as an upload. Keyed by Ember hash,
/// which the inbound Noise IK handshake proves.
pub(super) async fn register_or_refresh_pending_friend_callback(
    pending: &upload_server::PendingKadCallbacks,
    friend: [u8; 16],
    file_hash: [u8; 16],
) {
    let key = upload_server::PendingKadCallbackKey::FriendEmber(friend);
    let now = chrono::Utc::now().timestamp();
    let mut map = pending.lock().await;
    let entries = map.entry(key).or_default();
    if let Some(existing) = entries.iter_mut().find(|e| e.file_hash == file_hash) {
        existing.registered_at = now;
        return;
    }
    entries.push(upload_server::PendingKadCallbackEntry {
        file_hash,
        // Identity here is the Ember hash, so there is no port to
        // disambiguate on — `0` means "any", matching how the inbound matcher
        // treats an unknown advertised port.
        expected_tcp_port: 0,
        registered_at: now,
        origin: Some(crate::types::SourceOrigin::Ember),
    });
}

/// Minimum gap between inbound `OP_EMBER_XFER_REQ`s we will act on from one
/// friend. Comfortably below the requester's own
/// [`FRIEND_XFER_COOLDOWN_SECS`] so a well-behaved friend never trips it.
pub(super) const FRIEND_XFER_INBOUND_MIN_INTERVAL_SECS: u64 = 15;

/// Pure half of [`friend_transfer_request_status`]: given the facts about an
/// inbound `OP_EMBER_XFER_REQ`, return the `XFER_STATUS_*` code to ack with.
///
/// `last_inbound` is when we last accepted a request from this friend, and
/// `is_shared` whether we actually share the requested file. Both are looked up
/// behind locks by the caller; keeping them as parameters makes every decline
/// path testable.
pub(super) fn friend_xfer_inbound_status(
    is_friend: bool,
    request: &ed2k::messages::EmberXferRequest,
    peer_addr: SocketAddr,
    last_inbound: Option<std::time::Instant>,
    now: std::time::Instant,
    is_shared: bool,
    can_punch: bool,
) -> u8 {
    if !is_friend {
        return ed2k::messages::XFER_STATUS_DECLINED_NOT_SHARED;
    }

    match request.method {
        ed2k::messages::EmberXferMethod::ConnectBack => {
            // The dial target is the session's observed address, so a session we
            // can't derive a routable address from (a relay hop reports a
            // placeholder) can't be answered with a connect-back at all.
            let routable = match peer_addr.ip() {
                std::net::IpAddr::V4(v4) => !crate::security::is_special_use_v4(v4),
                std::net::IpAddr::V6(ip6) => {
                    !crate::security::is_private_ip(std::net::IpAddr::V6(ip6))
                }
            };
            if !routable || request.tcp_port == 0 {
                return ed2k::messages::XFER_STATUS_DECLINED_METHOD;
            }
        }
        ed2k::messages::EmberXferMethod::Punch => {
            // A punch needs no address from the payload — we read the friend's
            // from our rendezvous mailbox — but it does need our own punch
            // machinery to be usable.
            if !can_punch {
                return ed2k::messages::XFER_STATUS_DECLINED_METHOD;
            }
        }
    }

    if let Some(last) = last_inbound {
        if now.saturating_duration_since(last).as_secs() < FRIEND_XFER_INBOUND_MIN_INTERVAL_SECS {
            return ed2k::messages::XFER_STATUS_DECLINED_RATE_LIMITED;
        }
    }

    // Only dial for a file we actually share. Without this the request would
    // be a general-purpose "connect to this port" primitive, and the dial
    // would waste a connection to be refused at `OP_REQUESTFILENAME` anyway.
    if !is_shared {
        return ed2k::messages::XFER_STATUS_DECLINED_NOT_SHARED;
    }

    ed2k::messages::XFER_STATUS_ACCEPTED
}

/// Decide how to answer a friend's `OP_EMBER_XFER_REQ`, returning the
/// `XFER_STATUS_*` code to ack with. Accepting commits us to dialing them.
pub(super) async fn friend_transfer_request_status(
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    friend: [u8; 16],
    request: &ed2k::messages::EmberXferRequest,
    peer_addr: SocketAddr,
    friend_hashes: &Arc<RwLock<HashSet<[u8; 16]>>>,
    mutual_friend_hashes: &Arc<RwLock<HashSet<[u8; 16]>>>,
) -> u8 {
    // Membership is re-read here rather than trusted from the dispatch site:
    // the friend could have been removed while this event sat in the channel.
    let is_friend = friend_hashes.read().await.contains(&friend);
    let hash_hex = hex::encode(request.file_hash);
    // Mere index presence used to be enough here, which would have handed a
    // friend an escalated transfer for a file we had explicitly unshared.
    // Require a live share, and a mutual friendship for a restricted one.
    // Both facts are lifted out under the index guard, which is then dropped
    // before the membership lookup. Holding it across that second lock was not
    // a deadlock — nothing in the codebase ever takes `mutual_friend_hashes`
    // and then wants `local_index`, so the order is one-directional — but it
    // was the only place that nested the two, and the equivalent checks in
    // `resolve_upload_file` already reads the file out first. Keeping one order everywhere is what makes that property
    // easy to keep true.
    let restriction = {
        let index = local_index.read().await;
        index
            .get_by_hash(&hash_hex)
            .map(|file| (file.friends_only, file.is_friend_visible()))
    };
    let is_shared = match restriction {
        Some((true, visible)) => {
            visible && mutual_friend_hashes.read().await.contains(&friend)
        }
        Some((false, visible)) => visible,
        None => false,
    };
    let now = std::time::Instant::now();

    // Whether we could take part in a coordinated punch. Deliberately the same
    // predicate the requester uses on itself, so both sides agree on when a
    // punch is worth attempting.
    let can_punch = friend_xfer_transport_choice(
        true, // ignore our own TCP reachability: the friend asked for a punch
        0,
        advertised_quic_port(state),
        state.nat_info.nat_type,
        state.nat_info.external_addr,
        state.rendezvous_registered,
    )
    .is_ok();

    let status = friend_xfer_inbound_status(
        is_friend,
        request,
        peer_addr,
        state.friend_xfer_inbound_last.get(&friend).copied(),
        now,
        is_shared,
        can_punch,
    );
    if status == ed2k::messages::XFER_STATUS_ACCEPTED {
        state.friend_xfer_inbound_last.insert(friend, now);
        state.friend_xfer_stats.inbound_accepted =
            state.friend_xfer_stats.inbound_accepted.saturating_add(1);
        if request.method == ed2k::messages::EmberXferMethod::Punch {
            // Arm the punch responder to take the serve role for this friend.
            state.friend_xfer_punch_serve.insert(friend, now);
        }
    } else {
        state.friend_xfer_stats.inbound_declined =
            state.friend_xfer_stats.inbound_declined.saturating_add(1);
        debug!(
            "Declining transfer request from friend {} for {hash_hex} ({peer_addr} port {}): status {status}",
            hex::encode(friend),
            request.tcp_port
        );
    }
    status
}

/// Give up an accepted transfer whose punch cannot happen: release the source
/// for ordinary retry, as a decline does. A no-op once the attempt is gone (it
/// timed out, or the friend's dial already arrived and took it).
pub(super) async fn abandon_friend_transfer_attempt(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    pending: &upload_server::PendingKadCallbacks,
    app_handle: &tauri::AppHandle,
    friend: [u8; 16],
    nonce: [u8; 16],
) {
    let Some((key, transfer_id)) = take_abandoned_friend_xfer_attempt(
        &mut state.friend_xfer_attempts,
        friend,
        nonce,
        std::time::Instant::now(),
    ) else {
        return;
    };
    drop_pending_friend_callback(pending, friend, key.1).await;
    release_friend_connect_sources(state, transfer_manager, app_handle, &transfer_id).await;
    release_sources_waiting_on_friend(state, transfer_manager, app_handle, friend).await;
}

/// Pure half of [`abandon_friend_transfer_attempt`]: remove the attempt
/// `nonce` answers and return it with its transfer, or `None` to leave things
/// as they are.
fn take_abandoned_friend_xfer_attempt(
    attempts: &mut HashMap<([u8; 16], [u8; 16]), FriendXferAttempt>,
    friend: [u8; 16],
    nonce: [u8; 16],
    now: std::time::Instant,
) -> Option<(([u8; 16], [u8; 16]), String)> {
    let key = find_friend_xfer_attempt(attempts, friend, nonce)?;
    // A registration that failed only after the attempt timed out finds the
    // record the timeout sweep deliberately kept: it carries the retry count
    // and cooldown, and the sweep has already released the sources. Removing
    // it would reset both, and a second release could free a source parked
    // since for another friend.
    if now.saturating_duration_since(attempts[&key].sent_at).as_secs()
        >= FRIEND_XFER_ATTEMPT_TIMEOUT_SECS
    {
        return None;
    }
    attempts.remove(&key).map(|attempt| (key, attempt.transfer_id))
}

/// Mark the attempt under `key` accepted. `true` only for the first accept,
/// so a repeated ack neither counts twice nor registers a second punch.
fn first_friend_xfer_accept(
    attempts: &mut HashMap<([u8; 16], [u8; 16]), FriendXferAttempt>,
    key: &([u8; 16], [u8; 16]),
) -> bool {
    match attempts.get_mut(key) {
        Some(attempt) if !attempt.accepted => {
            attempt.accepted = true;
            true
        }
        _ => false,
    }
}

/// Apply a friend's answer to our own `OP_EMBER_XFER_REQ`.
///
/// An accept is informational: the inbound expectation was registered when the
/// request went out, so their dial is already routable to the download. A
/// decline drops that expectation and releases the source for ordinary retry
/// rather than making it wait out the full attempt timeout.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_friend_transfer_ack(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    pending: &upload_server::PendingKadCallbacks,
    app_handle: &tauri::AppHandle,
    ul_event_tx: &mpsc::Sender<upload_server::UploadEvent>,
    settings: &AppSettings,
    ed25519_secret_key: [u8; 32],
    ember_hash: [u8; 16],
    friend: [u8; 16],
    status: u8,
    nonce: [u8; 16],
) {
    let Some(key) = find_friend_xfer_attempt(&state.friend_xfer_attempts, friend, nonce) else {
        debug!(
            "Ignoring transfer ack from friend {} with unknown nonce",
            hex::encode(friend)
        );
        return;
    };
    let transfer_id = state.friend_xfer_attempts[&key].transfer_id.clone();
    let attempt_transport = state.friend_xfer_attempts[&key].transport;

    if status == ed2k::messages::XFER_STATUS_ACCEPTED {
        if !first_friend_xfer_accept(&mut state.friend_xfer_attempts, &key) {
            debug!(
                "Ignoring a repeated transfer accept from friend {} for {}",
                hex::encode(friend),
                hex::encode(key.1)
            );
            return;
        }
        state.friend_xfer_stats.accepted = state.friend_xfer_stats.accepted.saturating_add(1);
        debug!(
            "Friend {} accepted our transfer request for {}",
            hex::encode(friend),
            hex::encode(key.1)
        );
        // Publish our punch registration only now, on acceptance.
        //
        // Registering before sending the request looks more eager but opens a
        // race: until the friend has accepted, its punch responder has no idea
        // the registration belongs to a transfer, so an idle mailbox poll
        // landing in that window would treat ours as an ordinary *social*
        // punch, take the inbound role, and consume the entry — leaving both
        // sides waiting for the other's `OP_HELLO`. Registering after the ack
        // means the entry only ever exists while the friend is already armed to
        // take the serve role, and the 30 s rendezvous TTL starts later too.
        if let FriendXferTransport::Punch { quic_port } = attempt_transport {
            // A registration we cannot publish means the punch can never
            // happen, even though the friend has already armed its serve role.
            // Release the source now rather than letting it idle out the full
            // attempt timeout — exactly what a decline does.
            let Some(external_addr) = state.nat_info.external_addr else {
                debug!(
                    "Punch accepted by {} but our external address is unknown",
                    hex::encode(friend)
                );
                abandon_friend_transfer_attempt(
                    state, transfer_manager, pending, app_handle, friend, nonce,
                )
                .await;
                return;
            };
            // Off the loop, like every other rendezvous call: a protocol
            // probe, an identity lookup and the register POST can take a
            // minute against a slow server, and awaited here they stalled
            // UDP, IPC and every timer for all of it.
            let rendezvous_url = settings.rendezvous_url.clone();
            let nat_type = state.nat_info.nat_type.as_u8();
            let failed_tx = ul_event_tx.clone();
            tokio::spawn(async move {
                let result = ember::relay::register_punch_with_ip(
                    &rendezvous_url,
                    &ember_hash,
                    &friend,
                    quic_port,
                    nat_type,
                    external_addr.ip(),
                    &ed25519_secret_key,
                    &ember_hash,
                )
                .await;
                if let Err(e) = result {
                    debug!(
                        "Could not register a transfer punch for friend {}: {e}",
                        hex::encode(friend)
                    );
                    let _ = failed_tx
                        .send(upload_server::UploadEvent {
                            transfer_id: String::new(),
                            kind: upload_server::UploadEventKind::FriendTransferPunchFailed {
                                friend,
                                nonce,
                            },
                        })
                        .await;
                }
            });
        }
        return;
    }

    let reason = match status {
        ed2k::messages::XFER_STATUS_DECLINED_NOT_SHARED => "no longer shares the file",
        ed2k::messages::XFER_STATUS_DECLINED_RATE_LIMITED => "is rate-limiting our requests",
        ed2k::messages::XFER_STATUS_DECLINED_METHOD => "cannot reach us that way",
        _ => "declined for an unknown reason",
    };
    state.friend_xfer_stats.declined = state.friend_xfer_stats.declined.saturating_add(1);
    info!(
        "Friend {} {reason}; releasing source for {}",
        hex::encode(friend),
        hex::encode(key.1)
    );

    state.friend_xfer_attempts.remove(&key);
    drop_pending_friend_callback(pending, friend, key.1).await;
    release_friend_connect_sources(state, transfer_manager, app_handle, &transfer_id).await;
    release_sources_waiting_on_friend(state, transfer_manager, app_handle, friend).await;
}

/// Whether `peer` refuses `file_hash` on a plain eD2K connection, so a download
/// must reach them by friend transfer instead.
///
/// A friend serves friends-only content only on an authenticated secure-v2
/// session, and charges every plain-eD2K miss to its hash-probe counter, which
/// bans the asker after a handful of distinct hashes. So asking first and
/// escalating on the refusal is not free: a browse queue of friends-only files
/// got us banned by the friend we were downloading from.
///
/// The friend's browse scope reports exactly the set its upload side treats as
/// restricted. `transfer_friends_only` stands in for it once a restart has
/// cleared that in-memory record; it can also name a friend who shares the file
/// publicly, which costs only the faster transport, never a ban.
pub(crate) fn friend_refuses_plain_ed2k(
    peer: Option<[u8; 16]>,
    friend_hashes: &HashSet<[u8; 16]>,
    file_hash: &[u8; 16],
    transfer_friends_only: bool,
) -> bool {
    let Some(friend) = peer.filter(|id| friend_hashes.contains(id)) else {
        return false;
    };
    transfer_friends_only || super::browse::friend_marked_friends_only(friend, file_hash)
}

/// Whether [`friend_refuses_plain_ed2k`] could hold for some source of this
/// download: a source whose identity is not known yet then has to name it
/// before it is asked for the file. Every other download asks at once.
pub(crate) fn friend_transfer_only_possible(
    friend_hashes: &HashSet<[u8; 16]>,
    file_hash: &[u8; 16],
    transfer_friends_only: bool,
) -> bool {
    !friend_hashes.is_empty()
        && (transfer_friends_only
            || friend_hashes
                .iter()
                .any(|friend| super::browse::friend_marked_friends_only(*friend, file_hash)))
}

/// A dial to `(ip, port)` for `transfer_id` just failed. If that download came
/// from a friend's file listing, ask the friend to reach us instead of marking
/// the source dead.
///
/// Returns whether the source was parked, in which case the caller must leave
/// the dead-source bookkeeping alone. Parking means one of two things: the
/// request went out and the source waits in
/// [`DownloadSourceState::FriendConnect`] until the friend arrives, declines,
/// or the attempt times out; or no transport could be offered at all and it
/// sits in [`DownloadSourceState::Unreachable`], which explains the dead end
/// in the drawer and clears itself once our reachability changes.
#[allow(clippy::too_many_arguments)]
pub(super) async fn maybe_escalate_to_friend_transfer(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    credit_manager: &Arc<RwLock<CreditManager>>,
    friend_hashes: &Arc<RwLock<HashSet<[u8; 16]>>>,
    pending: &upload_server::PendingKadCallbacks,
    app_handle: &tauri::AppHandle,
    transfer_id: &str,
    ip: Ipv4Addr,
    port: u16,
) -> bool {
    // Who this particular source is, where we can tell. `sources.met` remembers
    // its ed2k user hash and `clients.met` the Ember identity bound to that
    // hash, so a friend stays recognisable however the source reached us — an
    // eD2K link, a search hit, KAD, peer exchange — and across the restart that
    // clears the in-memory browse binding.
    //
    // Resolved from *this download's* own source row rather than a
    // `SourceManager`-wide address lookup: the wide lookup scans every tracked
    // file and ignores entry expiry, so an address recycled from a departed peer
    // would still resolve to that peer.
    let source_identity = {
        let peer_user_hash = state
            .per_file_sources
            .get(transfer_id)
            .and_then(|pfs| pfs.source_user_hash_at(ip, port));
        match peer_user_hash {
            Some(uh) => credit_manager.read().await.find_ember_by_user_hash(&uh),
            None => None,
        }
    };

    let friend = match source_identity {
        // We know whose source this is, so it decides — and it takes precedence
        // over the per-transfer binding deliberately. That binding says only
        // that the *download* came from a friend's listing, and a download
        // collects sources from KAD, servers and peer exchange too. Letting it
        // speak for a source we can positively identify as someone else charged
        // a stranger's failure to the friend's attempt budget and parked the
        // stranger's row as though it were awaiting the friend's dial-back,
        // which froze it out of reask until the request timed out.
        Some(id) => {
            if !friend_hashes.read().await.contains(&id) {
                return false;
            }
            debug!(
                "Recognised source {ip}:{port} on {transfer_id} as friend {} by stored identity",
                hex::encode(id)
            );
            id
        }
        // No identity recorded for this address, so we cannot rule out that it
        // is the friend the download came from — which is exactly the gap the
        // browse binding exists to cover. The hint still has to name a current
        // friend: it outlives the friendship, so after the user removes that
        // friend an unidentifiable source was parked as "awaiting the friend's
        // connect-back" and frozen out of reask until the request timed out —
        // the same failure the `Some(id)` branch above is guarding against.
        None => match state.transfer_friend_hint.get(transfer_id).copied() {
            Some(friend) if friend_hashes.read().await.contains(&friend) => friend,
            _ => return false,
        },
    };
    let Some(file_hash) = transfer_file_hash(transfer_manager, transfer_id).await else {
        return false;
    };

    // A dead end is parked too, not just a live request. Both cases keep the
    // row visible and both stop the caller's dead-source bookkeeping; they
    // differ only in what the row says and whether anything is outstanding.
    let unreachable =
        match request_friend_transfer(state, pending, transfer_id, friend, file_hash).await {
            FriendXferRequestOutcome::Sent => false,
            FriendXferRequestOutcome::NoTransport(reason) => {
                info!(
                    "No transport to offer friend {} for {}: {reason:?}",
                    hex::encode(friend),
                    hex::encode(file_hash)
                );
                true
            }
            FriendXferRequestOutcome::Outstanding | FriendXferRequestOutcome::Refused => {
                return false
            }
        };
    park_friend_source(state, transfer_manager, app_handle, transfer_id, ip, port, unreachable)
        .await;
    true
}

/// The download worker stopped short of asking `friend` for this download's
/// file over plain eD2K, which the friend refuses ([`friend_refuses_plain_ed2k`]
/// said so for the identity the worker saw). Ask for a friend transfer instead.
///
/// Never a source failure, whatever the answer: nothing was asked of the
/// friend, so no fail count, no dead-source entry and no reputation event.
/// The source is parked either way so that nothing re-dials it meanwhile:
/// waiting for the friend's connect-back, waiting on a request to that friend
/// already in flight (released with it, see [`release_sources_waiting_on_friend`]),
/// or, when no request can go out at all, `Unreachable` until the ordinary
/// reask cadence tries again.
#[allow(clippy::too_many_arguments)]
pub(super) async fn route_friend_transfer_only_source(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    friend_hashes: &Arc<RwLock<HashSet<[u8; 16]>>>,
    pending: &upload_server::PendingKadCallbacks,
    app_handle: &tauri::AppHandle,
    transfer_id: &str,
    ip: Ipv4Addr,
    port: u16,
    friend: [u8; 16],
) {
    if !friend_hashes.read().await.contains(&friend) {
        return;
    }
    let Some(file_hash) = transfer_file_hash(transfer_manager, transfer_id).await else {
        return;
    };
    let outcome = request_friend_transfer(state, pending, transfer_id, friend, file_hash).await;
    let unreachable = friend_transfer_only_parking(
        &mut state.friend_xfer_waiting,
        outcome,
        friend,
        transfer_id,
    );
    park_friend_source(state, transfer_manager, app_handle, transfer_id, ip, port, unreachable)
        .await;
}

/// Pure half of [`route_friend_transfer_only_source`]: whether the source is
/// parked `Unreachable` rather than `FriendConnect`, noting `transfer_id` as
/// waiting on `friend` when it is held only by a request already in flight.
pub(super) fn friend_transfer_only_parking(
    waiting: &mut HashMap<[u8; 16], HashSet<String>>,
    outcome: FriendXferRequestOutcome,
    friend: [u8; 16],
    transfer_id: &str,
) -> bool {
    match outcome {
        FriendXferRequestOutcome::Sent => false,
        FriendXferRequestOutcome::Outstanding => {
            waiting
                .entry(friend)
                .or_default()
                .insert(transfer_id.to_string());
            false
        }
        FriendXferRequestOutcome::NoTransport(_) | FriendXferRequestOutcome::Refused => true,
    }
}

/// A request to `friend` is over — answered, declined, connected or timed
/// out — so sources parked waiting their turn behind it may ask now.
pub(super) async fn release_sources_waiting_on_friend(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    app_handle: &tauri::AppHandle,
    friend: [u8; 16],
) {
    for transfer_id in take_sources_waiting_on_friend(&mut state.friend_xfer_waiting, friend) {
        release_friend_connect_sources(state, transfer_manager, app_handle, &transfer_id).await;
    }
}

/// Whether any request to `friend` is still inside its timeout. The downloads
/// waiting on that friend are parked behind such a request, so a different
/// request to the same friend timing out must not release them.
pub(super) fn friend_has_live_request(
    attempts: &HashMap<([u8; 16], [u8; 16]), FriendXferAttempt>,
    friend: [u8; 16],
    now: std::time::Instant,
) -> bool {
    attempts.iter().any(|((f, _), attempt)| {
        *f == friend
            && now.saturating_duration_since(attempt.sent_at).as_secs()
                < FRIEND_XFER_ATTEMPT_TIMEOUT_SECS
    })
}

/// The transfers waiting on `friend`, forgotten as they are returned so a
/// second ending for the same request releases nothing.
fn take_sources_waiting_on_friend(
    waiting: &mut HashMap<[u8; 16], HashSet<String>>,
    friend: [u8; 16],
) -> HashSet<String> {
    waiting.remove(&friend).unwrap_or_default()
}

async fn transfer_file_hash(
    transfer_manager: &Arc<RwLock<TransferManager>>,
    transfer_id: &str,
) -> Option<[u8; 16]> {
    let mgr = transfer_manager.read().await;
    parse_ed2k_hash16(&mgr.get_transfer(transfer_id)?.file_hash)
}

/// Park `(ip, port)` of `transfer_id` as waiting on a friend transfer
/// (`FriendConnect`) or as having no way to one (`Unreachable`), in the live
/// source list and the stored row alike.
async fn park_friend_source(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    app_handle: &tauri::AppHandle,
    transfer_id: &str,
    ip: Ipv4Addr,
    port: u16,
    unreachable: bool,
) {
    if let Some(pfs) = state.per_file_sources.get_mut(transfer_id) {
        park_in_source_list(pfs, ip, port, unreachable);
    }
    let (parked_status, parked_status_str) = if unreachable {
        (crate::types::SourceStatus::Unreachable, "unreachable")
    } else {
        (crate::types::SourceStatus::FriendConnect, "friend_connect")
    };
    let ip_s = ip.to_string();
    // Park the *stored* row, not just the live one. A failed dial's caller
    // stops the originating `"failed"` event (see its `friend_escalated`
    // guard), so nothing downstream will move this row off the state the
    // failed dial left it in — and the drawer drops a `Failed` row entirely
    // rather than showing a source that is healthily waiting for the friend.
    let transferred = {
        let mut mgr = transfer_manager.write().await;
        // `update_source_detail` overwrites `transferred` unconditionally;
        // carry the existing value so parking the row doesn't reset the
        // byte count this source already contributed.
        let transferred = mgr
            .get_source_details(transfer_id)
            .into_iter()
            .find(|s| s.ip == ip_s && s.port == port)
            .map(|s| s.transferred)
            .unwrap_or(0);
        mgr.update_source_detail(
            transfer_id,
            crate::types::SourceInfo {
                ip: ip_s.clone(),
                port,
                status: parked_status,
                queue_rank: None,
                speed: 0,
                transferred,
                client_software: String::new(),
                peer_name: String::new(),
                available_parts: None,
                total_parts: None,
                country_code: None,
                user_hash: None,
                // Parking an existing row, not discovering a source: the merge
                // in `update_source_detail` keeps whatever origin it has.
                origin: None,
                placeholder: false,
            },
        );
        transferred
    };
    let _ = app_handle.emit(
        "transfer-source-detail",
        serde_json::json!({
            "transfer_id": transfer_id,
            "ip": ip_s,
            "port": port,
            "status": parked_status_str,
            "queue_rank": null,
            "speed": 0,
            // The same value the stored row keeps. Sending 0 here undid the
            // preservation immediately above: the drawer took the event as
            // truth and blanked the byte count until something refetched.
            "transferred": transferred,
            "client_software": "",
            "peer_name": "",
            "available_parts": null,
            "total_parts": null,
            "country_code": null,
        }),
    );
}

/// The live-list half of [`park_friend_source`].
pub(super) fn park_in_source_list(
    pfs: &mut ed2k::sources::PerFileSourceList,
    ip: Ipv4Addr,
    port: u16,
    unreachable: bool,
) {
    if unreachable {
        pfs.set_unreachable(ip, port, None);
    } else {
        pfs.set_friend_connect(ip, port, None);
    }
}

/// Drop every `FriendEmber` expectation with no corresponding live entry in
/// `live` (the keys of `friend_xfer_attempts`, the single source of truth).
///
/// One reconciliation pass covers every way an attempt can disappear — decline,
/// timeout, cancel, delete, or the transfer leaving the manager — instead of
/// each of those paths having to remember to unregister. Non-friend keys
/// (`SourceIp` / `SourceUserHash`) are left strictly alone: they belong to the
/// eD2K and KAD callback bookkeeping, which has its own TTL sweep.
pub(super) fn reconcile_friend_pending_callbacks(
    map: &mut HashMap<
        upload_server::PendingKadCallbackKey,
        Vec<upload_server::PendingKadCallbackEntry>,
    >,
    live: &HashSet<([u8; 16], [u8; 16])>,
) {
    map.retain(|key, entries| {
        let upload_server::PendingKadCallbackKey::FriendEmber(friend) = key else {
            return true;
        };
        entries.retain(|e| live.contains(&(*friend, e.file_hash)));
        !entries.is_empty()
    });
}

/// Forget the expectation that `friend` will dial us for `file_hash`.
pub(super) async fn drop_pending_friend_callback(
    pending: &upload_server::PendingKadCallbacks,
    friend: [u8; 16],
    file_hash: [u8; 16],
) {
    let key = upload_server::PendingKadCallbackKey::FriendEmber(friend);
    let mut map = pending.lock().await;
    if let Some(entries) = map.get_mut(&key) {
        entries.retain(|e| e.file_hash != file_hash);
        if entries.is_empty() {
            map.remove(&key);
        }
    }
}

/// Return every source of `transfer_id` parked in
/// [`DownloadSourceState::FriendConnect`] to ordinary retry, and refresh the
/// UI rows so they stop showing a connect-back that is no longer coming.
pub(super) async fn release_friend_connect_sources(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    app_handle: &tauri::AppHandle,
    transfer_id: &str,
) {
    let released = {
        let Some(pfs) = state.per_file_sources.get_mut(transfer_id) else {
            return;
        };
        release_friend_connect_in_list(pfs, std::time::Instant::now())
    };
    if released.is_empty() {
        return;
    }
    // Mirror the emitted `"failed"` onto the stored row.
    // `maybe_escalate_to_friend_transfer` parked it as `FriendConnect`, so
    // without this the drawer would re-read that stale row on refresh and go on
    // showing a connect-back that is no longer coming.
    let mut released_bytes = Vec::with_capacity(released.len());
    {
        let mut mgr = transfer_manager.write().await;
        let existing = mgr.get_source_details(transfer_id);
        for (ip, port) in &released {
            let ip_s = ip.to_string();
            // `update_source_detail` overwrites `transferred` unconditionally;
            // carry the existing value so releasing the row doesn't reset the
            // byte count this source already contributed.
            let transferred = existing
                .iter()
                .find(|s| s.ip == ip_s && s.port == *port)
                .map(|s| s.transferred)
                .unwrap_or(0);
            mgr.update_source_detail(
                transfer_id,
                crate::types::SourceInfo {
                    ip: ip_s,
                    port: *port,
                    status: crate::types::SourceStatus::Failed,
                    queue_rank: None,
                    speed: 0,
                    transferred,
                    client_software: String::new(),
                    peer_name: String::new(),
                    available_parts: None,
                    total_parts: None,
                    country_code: None,
                    user_hash: None,
                    // Releasing an existing row — see the parking site.
                    origin: None,
                    placeholder: false,
                },
            );
            released_bytes.push((*ip, *port, transferred));
        }
    }
    for (ip, port, transferred) in released_bytes {
        let _ = app_handle.emit(
            "transfer-source-detail",
            serde_json::json!({
                "transfer_id": transfer_id,
                "ip": ip.to_string(),
                "port": port,
                "status": "failed",
                "queue_rank": null,
                "speed": 0,
                // The same value the stored row keeps, for the reason spelled
                // out in `maybe_escalate_to_friend_transfer`: the drawer takes
                // this event as truth, so sending 0 undid the preservation
                // immediately above and blanked the byte count until a refetch.
                "transferred": transferred,
                "client_software": "",
                "peer_name": "",
                "available_parts": null,
                "total_parts": null,
                "country_code": null,
            }),
        );
    }
}

/// The live-list half of [`release_friend_connect_sources`]: every
/// `FriendConnect` source back to `Failed`, returned for the stored rows.
fn release_friend_connect_in_list(
    pfs: &mut ed2k::sources::PerFileSourceList,
    now: std::time::Instant,
) -> Vec<(Ipv4Addr, u16)> {
    pfs.friend_connect_sources(now)
        .into_iter()
        .map(|(ip, port, _)| {
            pfs.clear_friend_connect(ip, port, None);
            (ip, port)
        })
        .collect()
}

#[cfg(test)]
mod friend_transfer_tests {
    use super::*;
    use std::time::{Duration, Instant};

    const FRIEND_A: [u8; 16] = [0xAA; 16];
    const FRIEND_B: [u8; 16] = [0xBB; 16];
    const FILE_1: [u8; 16] = [0x11; 16];
    const FILE_2: [u8; 16] = [0x22; 16];

    fn attempt(
        transfer_id: &str,
        nonce: [u8; 16],
        sent_at: Instant,
        attempts: u32,
    ) -> FriendXferAttempt {
        FriendXferAttempt {
            transfer_id: transfer_id.to_string(),
            nonce,
            sent_at,
            attempts,
            transport: FriendXferTransport::ConnectBack { tcp_port: 4662 },
            accepted: false,
        }
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// A genuinely routable address. The `198.51.100.0/24` used elsewhere in
    /// these tests is RFC 5737 documentation space, which
    /// `is_special_use_v4` correctly refuses to dial — so it can't stand in for
    /// a reachable friend here.
    fn routable_addr() -> SocketAddr {
        "93.184.216.34:51000".parse().unwrap()
    }

    fn connect_back(file_hash: [u8; 16], tcp_port: u16) -> ed2k::messages::EmberXferRequest {
        ed2k::messages::EmberXferRequest {
            method: ed2k::messages::EmberXferMethod::ConnectBack,
            file_hash,
            tcp_port,
            nonce: [0x5A; 16],
        }
    }

    /// Only the first accept for a nonce goes on to count and register a
    /// punch; a repeat is ignored, and a fresh request starts unaccepted.
    #[test]
    fn a_repeated_accept_registers_no_second_punch() {
        let now = Instant::now();
        let key = (FRIEND_A, FILE_1);
        let mut attempts = HashMap::new();
        assert!(!first_friend_xfer_accept(&mut attempts, &key), "no attempt, nothing to accept");
        attempts.insert(key, attempt("t1", [1; 16], now, 1));
        assert!(first_friend_xfer_accept(&mut attempts, &key));
        assert!(!first_friend_xfer_accept(&mut attempts, &key));
        assert!(!first_friend_xfer_accept(&mut attempts, &key));
        attempts.insert(key, attempt("t1", [2; 16], now, 2));
        assert!(first_friend_xfer_accept(&mut attempts, &key), "a resend is a new request");
    }

    /// A friends-only source refused only because a request to that friend is
    /// already in flight waits on it; any other refusal is not "in flight".
    #[test]
    fn a_refusal_behind_a_request_in_flight_is_told_from_one_that_will_not_clear() {
        let now = Instant::now();
        let key = (FRIEND_A, FILE_1);
        let mut attempts = HashMap::new();
        assert!(friend_xfer_request_in_flight(
            FriendXferSendDecision::AnotherOutstanding,
            &attempts,
            key,
            now
        ));
        attempts.insert(key, attempt("t1", [1; 16], now - secs(10), 1));
        assert!(
            friend_xfer_request_in_flight(FriendXferSendDecision::Cooldown, &attempts, key, now),
            "this file's own request is still waiting on the friend"
        );
        attempts.insert(
            key,
            attempt("t1", [1; 16], now - secs(FRIEND_XFER_ATTEMPT_TIMEOUT_SECS + 1), 1),
        );
        assert!(
            !friend_xfer_request_in_flight(FriendXferSendDecision::Cooldown, &attempts, key, now),
            "a timed-out request will release nothing, so nothing may wait on it"
        );
        for refused in [FriendXferSendDecision::Exhausted, FriendXferSendDecision::NoUsableTransport] {
            assert!(!friend_xfer_request_in_flight(refused, &attempts, key, now));
        }
    }

    /// Only a download some friend may refuse over plain eD2K makes an
    /// unidentified source wait for its Ember identity.
    #[test]
    fn only_a_download_a_friend_may_refuse_waits_for_an_ember_identity() {
        let friend = [0xF5u8; 16];
        let marked = [0xE5u8; 16];
        let public = [0xE6u8; 16];
        let friends: HashSet<[u8; 16]> = [friend].into_iter().collect();
        browse::record_friend_offer(friend, marked, true);

        assert!(friend_transfer_only_possible(&friends, &public, true));
        assert!(friend_transfer_only_possible(&friends, &marked, false));
        assert!(!friend_transfer_only_possible(&friends, &public, false));
        assert!(
            !friend_transfer_only_possible(&HashSet::new(), &marked, true),
            "with no friends no source can be one"
        );
        browse::forget_friend_scope(friend);
    }

    #[test]
    fn plain_ed2k_is_refused_only_for_a_friend_restricting_the_file() {
        // Own hashes: the browse registry is process-wide.
        let friend = [0xF7u8; 16];
        let stranger = [0xF8u8; 16];
        let private = [0xE1u8; 16];
        let public = [0xE2u8; 16];
        let friends: HashSet<[u8; 16]> = [friend].into_iter().collect();
        browse::record_friend_offer(friend, private, true);
        browse::record_friend_offer(stranger, private, true);

        assert!(
            friend_refuses_plain_ed2k(Some(friend), &friends, &private, false),
            "the friend's browse scope restricts it"
        );
        assert!(
            friend_refuses_plain_ed2k(Some(friend), &friends, &public, true),
            "after a restart only the transfer's own flag remembers the scope"
        );
        assert!(
            !friend_refuses_plain_ed2k(Some(friend), &friends, &public, false),
            "a friend's public file still goes over plain eD2K"
        );
        assert!(
            !friend_refuses_plain_ed2k(Some(stranger), &friends, &private, true),
            "a source that is not a current friend dials normally"
        );
        assert!(
            !friend_refuses_plain_ed2k(None, &friends, &private, true),
            "an unidentified source dials normally"
        );

        browse::forget_friend_scope(friend);
        assert!(
            !friend_refuses_plain_ed2k(Some(friend), &friends, &private, false),
            "a lifted scope no longer diverts the dial"
        );
        browse::forget_friend_scope(stranger);
    }

    #[test]
    fn first_request_is_sent_and_no_transport_never_asks() {
        let now = Instant::now();
        let empty = HashMap::new();
        assert_eq!(
            friend_xfer_send_decision(true, &empty, FRIEND_A, FILE_1, now),
            FriendXferSendDecision::Send {
                previous_attempts: 0
            }
        );
        assert_eq!(
            friend_xfer_send_decision(false, &empty, FRIEND_A, FILE_1, now),
            FriendXferSendDecision::NoUsableTransport
        );
    }

    /// A reachable client prefers the connect-back: one TCP dial, no rendezvous
    /// round trip and no punch timing window to hit.
    #[test]
    fn reachable_client_prefers_connect_back_even_when_punch_is_possible() {
        assert_eq!(
            friend_xfer_transport_choice(
                false,
                4662,
                Some(4670),
                ember::nat::NatType::FullCone,
                Some("93.184.216.34:4670".parse().unwrap()),
                true,
            ),
            Ok(FriendXferTransport::ConnectBack { tcp_port: 4662 })
        );
    }

    /// The case Phase 1 could not serve: we are firewalled too, so ask for a
    /// coordinated punch instead of giving up.
    #[test]
    fn firewalled_client_falls_back_to_punch() {
        let choice = friend_xfer_transport_choice(
            true,
            4662,
            Some(4670),
            ember::nat::NatType::RestrictedCone,
            Some("93.184.216.34:4670".parse().unwrap()),
            true,
        );
        assert_eq!(choice, Ok(FriendXferTransport::Punch { quic_port: 4670 }));
        // Punch carries no port on the wire; the friend reads our address from
        // its rendezvous mailbox.
        let choice = choice.unwrap();
        assert_eq!(choice.wire_port(), 0);
        assert_eq!(choice.method(), ed2k::messages::EmberXferMethod::Punch);
    }

    /// Publishing used to take our own table's closest as the answer to "who is
    /// closest to this key", which it cannot be for a distant key: one bucket
    /// holds twenty nodes drawn from a huge range, while a searcher's walk
    /// converges on the true closest. Records therefore landed beside where
    /// lookups go looking.
    #[test]
    fn publish_targets_prefer_a_real_lookup_and_queue_the_key_until_they_have_one() {
        use std::collections::VecDeque;

        let local = ember::dht::EmberNodeId([0u8; 16]);
        let mut routing = ember::dht::routing::RoutingTable::new(local, false);
        for i in 0..4u8 {
            routing.add_contact(ember::dht::EmberContact {
                node_id: ember::dht::EmberNodeId([0x40 + i; 16]),
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, i + 1, 1)), 4672),
                noise_pub: [i; 32],
                ed25519_pub: [i; 32],
                last_seen: 1_700_000_000,
                failed_queries: 0,
            });
        }

        let key = [0xAB; 16];
        let now = 1_700_000_000i64;
        let mut cache: HashMap<[u8; 16], (Vec<ember::dht::EmberContact>, i64)> = HashMap::new();
        let mut queue: VecDeque<[u8; 16]> = VecDeque::new();
        // What a lookup files: the nodes that answered it, at the addresses they
        // answered from.
        let found = |id: ember::dht::EmberNodeId, octet: u8| ember::dht::EmberContact {
            node_id: id,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(81, 1, octet, 1)), 4672),
            noise_pub: [octet; 32],
            ed25519_pub: [octet; 32],
            last_seen: now,
            failed_queries: 0,
        };

        // Nothing learned yet: fall back to the table, but queue the key.
        let from_table = ember_publish_targets_for(&cache, &mut queue, EMBER_PUBLISH_TARGET_QUEUE_MAX, &routing, key, now);
        assert_eq!(from_table.len(), 4, "publishing must not stall on a lookup");
        assert_eq!(queue.len(), 1, "the key is queued for a real lookup");

        // Asking again must not queue it twice.
        let _ = ember_publish_targets_for(&cache, &mut queue, EMBER_PUBLISH_TARGET_QUEUE_MAX, &routing, key, now);
        assert_eq!(queue.len(), 1, "one entry per key");

        // A resolved lookup is resolved through the table: a node it still holds
        // is addressed where the table says. One it does not hold is used only
        // while the lookup is fresh, so a peer since evicted, faulted or filtered
        // out is not dialled at a remembered address for the entry's whole life.
        let known = ember::dht::EmberNodeId([0x41; 16]);
        let also_known = ember::dht::EmberNodeId([0x42; 16]);
        let evicted_since = ember::dht::EmberNodeId([0xAA; 16]);
        cache.insert(
            key,
            (
                vec![found(known, 9), found(also_known, 10), found(evicted_since, 11)],
                now,
            ),
        );
        queue.clear();
        let fresh = ember_publish_targets_for(&cache, &mut queue, EMBER_PUBLISH_TARGET_QUEUE_MAX, &routing, key, now);
        let held = fresh.iter().find(|c| c.node_id == known).expect("a target the table still holds is used");
        assert_eq!(
            held.addr,
            routing.get_contact(&known).unwrap().addr,
            "at the address the table holds, not the one remembered"
        );
        assert!(
            fresh.iter().any(|c| c.node_id == evicted_since),
            "a node the lookup just found is used though the table did not keep it"
        );
        assert!(
            queue.is_empty(),
            "an entry still carrying most of its set needs no new lookup"
        );

        let later = now + EMBER_PUBLISH_TARGETS_DETACHED_SECS;
        let aged = ember_publish_targets_for(&cache, &mut queue, EMBER_PUBLISH_TARGET_QUEUE_MAX, &routing, key, later);
        assert!(
            !aged.iter().any(|c| c.node_id == evicted_since),
            "once the lookup is no longer fresh, one the table no longer holds is not dialled"
        );

        // The set is topped up from our own closest, so a walk that converged
        // early — or an entry thinned by eviction — still fans out to as many
        // replicas as the table can offer.
        assert_eq!(
            aged.len(),
            4,
            "the shortfall is made up from the routing table"
        );

        // An entry inside its TTL whose nodes have mostly gone — evicted,
        // faulted or filtered out — has to ask again. Keying this on freshness alone
        // left it publishing to fallbacks for the rest of the entry's life, which is
        // worse than holding no entry at all.
        cache.insert(
            key,
            (
                vec![
                    found(evicted_since, 11),
                    found(ember::dht::EmberNodeId([0xBB; 16]), 12),
                ],
                now,
            ),
        );
        queue.clear();
        let all_gone = ember_publish_targets_for(&cache, &mut queue, EMBER_PUBLISH_TARGET_QUEUE_MAX, &routing, key, later);
        assert_eq!(
            queue.len(),
            1,
            "a set that no longer resolves queues a lookup"
        );
        assert!(
            !all_gone.is_empty(),
            "and still publishes meanwhile, from the table"
        );

        // And it is re-learned rather than trusted forever.
        cache.insert(key, (vec![found(known, 9)], now));
        queue.clear();
        let stale_at = now + EMBER_PUBLISH_TARGETS_TTL_SECS;
        let stale = ember_publish_targets_for(&cache, &mut queue, EMBER_PUBLISH_TARGET_QUEUE_MAX, &routing, key, stale_at);
        assert_eq!(queue.len(), 1, "an aged set queues the key again");
        assert!(
            !stale.is_empty(),
            "and still publishes meanwhile, from the table"
        );
    }

    /// Unverified leads (`last_seen == 0`) are worth pinging, but a STORE
    /// queued behind their handshake expires as a failure if they never
    /// answer. Publishing must wait for someone who has already PONGed.
    #[test]
    fn publish_targets_skip_unverified_leads() {
        use std::collections::VecDeque;

        let local = ember::dht::EmberNodeId([0u8; 16]);
        let mut routing = ember::dht::routing::RoutingTable::new(local, false);
        routing.add_contact(ember::dht::EmberContact {
            node_id: ember::dht::EmberNodeId([0x40; 16]),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, 1, 1)), 4672),
            noise_pub: [0x40; 32],
            ed25519_pub: [0x40; 32],
            last_seen: 0,
            failed_queries: 0,
        });
        routing.add_contact(ember::dht::EmberContact {
            node_id: ember::dht::EmberNodeId([0x41; 16]),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, 2, 1)), 4672),
            noise_pub: [0x41; 32],
            ed25519_pub: [0x41; 32],
            last_seen: 1_700_000_000,
            failed_queries: 0,
        });

        let key = [0xAB; 16];
        let now = 1_700_000_000i64;
        let mut cache: HashMap<[u8; 16], (Vec<ember::dht::EmberContact>, i64)> = HashMap::new();
        let mut queue: VecDeque<[u8; 16]> = VecDeque::new();

        let from_table = ember_publish_targets_for(&cache, &mut queue, EMBER_PUBLISH_TARGET_QUEUE_MAX, &routing, key, now);
        assert_eq!(from_table.len(), 1);
        assert!(from_table[0].is_verified());
        assert_eq!(from_table[0].node_id, ember::dht::EmberNodeId([0x41; 16]));

        // A lookup that remembered the lead must not revive it as a STORE
        // target either: resolve against the table as it is now, then skip
        // anyone still unverified — even when the lookup's own copy says it
        // answered, the table's word on a contact it holds wins.
        cache.insert(
            key,
            (
                vec![ember::dht::EmberContact {
                    node_id: ember::dht::EmberNodeId([0x40; 16]),
                    addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, 1, 1)), 4672),
                    noise_pub: [0x40; 32],
                    ed25519_pub: [0x40; 32],
                    last_seen: now,
                    failed_queries: 0,
                }],
                now,
            ),
        );
        queue.clear();
        let from_cache = ember_publish_targets_for(&cache, &mut queue, EMBER_PUBLISH_TARGET_QUEUE_MAX, &routing, key, now);
        assert!(
            !from_cache
                .iter()
                .any(|c| c.node_id == ember::dht::EmberNodeId([0x40; 16])),
            "an unverified cached ID must not be dialled for STORE"
        );
        assert!(
            from_cache.iter().all(|c| c.is_verified()),
            "top-up from the table must also skip leads"
        );
    }

    /// Session peers the public table refused still have to receive STOREs.
    /// Otherwise a LAN island with `block_private_ips` on searches those
    /// peers (FIND_VALUE pin) but never writes anything they can answer with.
    #[test]
    fn publish_targets_top_up_from_session_peers_the_table_refused() {
        use std::collections::VecDeque;

        let local = ember::dht::EmberNodeId([0u8; 16]);
        let routing = ember::dht::routing::RoutingTable::new(local, true);
        let cache: HashMap<[u8; 16], (Vec<ember::dht::EmberContact>, i64)> = HashMap::new();
        let mut queue: VecDeque<[u8; 16]> = VecDeque::new();
        let key = [0xCD; 16];
        let mut targets = ember_publish_targets_for(&cache, &mut queue, EMBER_PUBLISH_TARGET_QUEUE_MAX, &routing, key, 1_700_000_000);
        assert!(
            targets.is_empty(),
            "an empty public table has no closest contacts"
        );

        let session_peer = ember::dht::EmberContact {
            node_id: ember::dht::EmberNodeId([0x11; 16]),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 9)), 4672),
            noise_pub: [0x11; 32],
            ed25519_pub: [0x11; 32],
            last_seen: 1_700_000_000,
            failed_queries: 0,
        };
        let mut session = HashMap::new();
        session.insert(
            (Ipv4Addr::new(192, 168, 1, 9), 4672),
            session_peer.clone(),
        );
        ember_top_up_session_targets(&session, &mut targets);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].node_id, session_peer.node_id);

        let gossip = ember::dht::EmberContact {
            node_id: ember::dht::EmberNodeId([0x22; 16]),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 4672),
            noise_pub: [0x22; 32],
            ed25519_pub: [0x22; 32],
            last_seen: 0,
            failed_queries: 0,
        };
        session.insert((Ipv4Addr::new(192, 168, 1, 10), 4672), gossip);
        ember_top_up_session_targets(&session, &mut targets);
        assert_eq!(
            targets.len(),
            1,
            "unverified LAN gossip must not become a STORE target"
        );

        // Already holding the session peer must not duplicate it.
        ember_top_up_session_targets(&session, &mut targets);
        assert_eq!(targets.len(), 1);
    }

    /// `udp_firewalled` starts `true` and is only ever cleared by KAD's UDP
    /// probe, so with KAD switched off a node could never learn its port was
    /// open and advertised every source record as firewalled for the life of
    /// the process — relaying connections that did not need it. These are the
    /// two things Ember can establish on its own.
    #[test]
    fn ember_learns_its_udp_port_is_open_without_kad() {
        let now = 1_000_000i64;
        let ttl = EMBER_UDP_REACHABLE_TTL_SECS;

        // Nothing known yet: stay pessimistic and keep using a buddy.
        assert!(!ember_udp_reachable_from(
            ember::nat::NatType::Unknown,
            None,
            now
        ));
        assert!(!ember_udp_reachable_from(
            ember::nat::NatType::Symmetric,
            None,
            now
        ));
        // A cone NAT filters unsolicited inbound, so the type alone proves
        // nothing — this is the case that needs a peer to reach us.
        assert!(!ember_udp_reachable_from(
            ember::nat::NatType::PortRestricted,
            None,
            now
        ));

        // No NAT at all needs no peer to confirm it.
        assert!(ember_udp_reachable_from(
            ember::nat::NatType::Open,
            None,
            now
        ));

        // A stranger's PING settles it behind any NAT, and the proof ages out
        // so a network change we did not otherwise notice stops us claiming a
        // reachability we have lost.
        assert!(ember_udp_reachable_from(
            ember::nat::NatType::Symmetric,
            Some(now - ttl + 1),
            now
        ));
        assert!(!ember_udp_reachable_from(
            ember::nat::NatType::Symmetric,
            Some(now - ttl),
            now
        ));
        // A clock that jumped backwards must not read as fresh-forever or
        // panic on the subtraction.
        assert!(ember_udp_reachable_from(
            ember::nat::NatType::Symmetric,
            Some(now + 60),
            now
        ));
    }

    #[test]
    fn ember_tcp_firewalled_matches_publish_not_upnp_guess() {
        use crate::network::kad::firewall::FirewallStatus;
        assert!(
            !ember_tcp_firewalled_from(false, FirewallStatus::Unknown),
            "UPnP-pessimistic / unknown must not skip CALLBACK_REQ"
        );
        assert!(!ember_tcp_firewalled_from(false, FirewallStatus::Open));
        assert!(ember_tcp_firewalled_from(false, FirewallStatus::Firewalled));
        assert!(ember_tcp_firewalled_from(true, FirewallStatus::Open));
        assert!(ember_tcp_firewalled_from(true, FirewallStatus::Unknown));
    }

    /// A buddy that never endorsed the endpoint is not a callback destination.
    ///
    /// This used to be half of a pair: the other test pinned the compatibility
    /// trailer we published for peers too old to endorse. That trailer is gone —
    /// it shipped before wire v4, so every peer that can still reach us speaks
    /// endorsements, and a current build parks the source either way. What
    /// remains is the dial gate, which is the half that still has to hold: an
    /// unendorsed buddy can arrive from anywhere, and must never be dialled.
    #[test]
    fn an_unendorsed_buddy_is_never_dialled() {
        let src = ember::dht::publish::DiscoveredSource {
            ip: Ipv4Addr::new(10, 0, 0, 9),
            tcp_port: 4662,
            udp_port: 4672,
            flags: ember::SOURCE_FLAG_FIREWALLED,
            user_hash: Some([0xCCu8; 16]),
            buddy: Some(ember::dht::publish::SourceBuddy {
                ip: Ipv4Addr::new(8, 8, 4, 4),
                udp_port: 4672,
                noise_pub: [0x11; 32],
                ed25519_pub: [0u8; 32],
                endorsed_until: 0,
                endorsement: [0u8; 64],
            }),
            callback_token: Some([0xDDu8; 16]),
            publisher_id: [0xAAu8; 16],
            quic_port: None,
        };
        assert!(
            !ember_source_uses_callback(&src, false, false, true, 1_000),
            "no identity key means no endorsement to check, so the source parks"
        );
    }

    #[test]
    fn ember_source_uses_callback_parks_unusable_buddies() {
        let now = 1_000_000i64;
        let publisher_id = [0xAAu8; 16];
        let buddy_sk = ed25519_dalek::SigningKey::from_bytes(&[0xB4u8; 32]);
        let buddy_ip = Ipv4Addr::new(8, 8, 4, 4);
        let buddy_noise = [0xB1u8; 32];
        let until = now + 3600;
        let buddy = ember::dht::publish::SourceBuddy {
            ip: buddy_ip,
            udp_port: 4672,
            noise_pub: buddy_noise,
            ed25519_pub: buddy_sk.verifying_key().to_bytes(),
            endorsed_until: until,
            endorsement: ember::crypto::sign(
                &buddy_sk,
                &ember::dht::publish::buddy_endorsement_signing_bytes(
                    buddy_ip,
                    4672,
                    &buddy_noise,
                    &publisher_id,
                    until,
                ),
            ),
        };
        let src = ember::dht::publish::DiscoveredSource {
            ip: Ipv4Addr::new(10, 0, 0, 9),
            tcp_port: 4662,
            udp_port: 4672,
            flags: ember::SOURCE_FLAG_FIREWALLED,
            user_hash: Some([0xCCu8; 16]),
            buddy: Some(buddy),
            callback_token: Some([0xDDu8; 16]),
            publisher_id,
            quic_port: None,
        };
        assert!(ember_source_uses_callback(&src, false, false, true, now));
        assert!(
            !ember_source_uses_callback(&src, true, false, true, now),
            "firewalled searcher parks rather than CALLBACK_REQ"
        );
        assert!(
            !ember_source_uses_callback(&src, false, true, true, now),
            "filtered or banned buddy must fall back to park, not drop"
        );
        assert!(
            !ember_source_uses_callback(&src, false, false, true, until + 1),
            "a lapsed endorsement parks too"
        );
        assert!(
            !ember_source_uses_callback(&src, false, false, false, now),
            "an endorsement no verified contact corroborates parks: the signature \
             is made with a key the publisher supplies, so it names nobody"
        );

        let lan = ember::dht::publish::DiscoveredSource {
            buddy: Some(ember::dht::publish::SourceBuddy {
                ip: Ipv4Addr::new(192, 168, 0, 2),
                ..buddy
            }),
            ..src
        };
        assert!(
            !ember_source_uses_callback(&lan, false, false, true, now),
            "special-use buddy is not a callback job"
        );

        let unendorsed = ember::dht::publish::DiscoveredSource {
            buddy: Some(ember::dht::publish::SourceBuddy {
                ed25519_pub: [0u8; 32],
                ..buddy
            }),
            ..src
        };
        assert!(
            !ember_source_uses_callback(&unendorsed, false, false, true, now),
            "a trailer published before endorsements existed has nothing to bind"
        );

        let aimed_elsewhere = ember::dht::publish::DiscoveredSource {
            buddy: Some(ember::dht::publish::SourceBuddy {
                ip: Ipv4Addr::new(9, 9, 9, 9),
                ..buddy
            }),
            ..src
        };
        assert!(
            !ember_source_uses_callback(&aimed_elsewhere, false, false, true, now),
            "an endpoint its owner did not sign for is a reflection target"
        );

        assert!(
            !ember_source_is_sm_dialable(&src),
            "FIREWALLED contacts must not be registered in SourceManager"
        );
        let highid = ember::dht::publish::DiscoveredSource {
            flags: 0,
            buddy: None,
            callback_token: None,
            ..src
        };
        assert!(ember_source_is_sm_dialable(&highid));
    }

    #[test]
    fn ember_firewalled_source_should_broker_matches_kad_ember_capable_gate() {
        let ip = Ipv4Addr::new(8, 8, 8, 8);
        assert!(
            ember_firewalled_source_should_broker(
                true,
                ember::SOURCE_FLAG_FIREWALLED | ember::SOURCE_FLAG_RELAY_CAPABLE,
                ip,
                4662,
            ),
            "two firewalled Ember peers must start the broker"
        );
        assert!(
            !ember_firewalled_source_should_broker(
                false,
                ember::SOURCE_FLAG_FIREWALLED | ember::SOURCE_FLAG_RELAY_CAPABLE,
                ip,
                4662,
            ),
            "reachable searcher uses CALLBACK_REQ, not the broker"
        );
        assert!(
            !ember_firewalled_source_should_broker(
                true,
                ember::SOURCE_FLAG_FIREWALLED,
                ip,
                4662,
            ),
            "without RELAY_CAPABLE, admission already refuses LowID↔LowID"
        );
        assert!(!ember_firewalled_source_should_broker(
            true,
            ember::SOURCE_FLAG_FIREWALLED | ember::SOURCE_FLAG_RELAY_CAPABLE,
            Ipv4Addr::UNSPECIFIED,
            4662,
        ));
        assert!(!ember_firewalled_source_should_broker(
            true,
            ember::SOURCE_FLAG_FIREWALLED | ember::SOURCE_FLAG_RELAY_CAPABLE,
            ip,
            0,
        ));
    }

    #[test]
    fn epx_marks_ember_relay_as_firewalled() {
        use ed2k::sources::DownloadSourceState::*;
        assert!(epx_advertises_source_firewalled(&WaitCallbackKad));
        assert!(epx_advertises_source_firewalled(&LowToLowIp));
        assert!(
            epx_advertises_source_firewalled(&EmberRelay),
            "broker-parked firewalled contacts must not be gossiped as HighID"
        );
        assert!(!epx_advertises_source_firewalled(&New));
        assert!(!epx_advertises_source_firewalled(&Failed));
        assert!(!epx_advertises_source_firewalled(&FriendConnect));
    }

    #[test]
    fn ember_udp_fail_closed_still_admits_known_peers() {
        // Strangers wait until ipfilter.dat is applied.
        assert!(!ember_udp_ip_filter_allows(
            false, true, || false, false, || false
        ));
        // Restored / just-dialled contacts must get their pongs through.
        assert!(ember_udp_ip_filter_allows(
            false, true, || true, false, || false
        ));
        assert!(ember_udp_ip_filter_allows(
            false, true, || false, false, || true
        ));
        // After the list is ready, a real block is LAN-session only.
        assert!(!ember_udp_ip_filter_allows(
            true, false, || true, false, || false
        ));
        assert!(ember_udp_ip_filter_allows(
            true, false, || true, true, || true
        ));
        assert!(ember_udp_ip_filter_allows(
            false, false, || false, false, || false
        ));
    }

    /// The peer predicates are lazy, and being lazy changes no verdict: every
    /// input gives the answer the eager form gave, and a predicate is asked
    /// only when that answer depends on it.
    #[test]
    fn ember_udp_ip_filter_asks_peer_predicates_only_when_they_decide() {
        let eager = |blocked: bool, fail_closed: bool, known: bool, lan: bool, introduced: bool| {
            if fail_closed {
                known || introduced
            } else if blocked {
                lan && introduced
            } else {
                true
            }
        };
        for bits in 0..32u8 {
            let [blocked, fail_closed, known, lan, introduced] =
                [0, 1, 2, 3, 4].map(|bit| bits & (1 << bit) != 0);
            let known_asked = std::cell::Cell::new(false);
            let introduced_asked = std::cell::Cell::new(false);
            let verdict = ember_udp_ip_filter_allows(
                blocked,
                fail_closed,
                || {
                    known_asked.set(true);
                    known
                },
                lan,
                || {
                    introduced_asked.set(true);
                    introduced
                },
            );
            assert_eq!(
                verdict,
                eager(blocked, fail_closed, known, lan, introduced),
                "blocked={blocked} fail_closed={fail_closed} known={known} lan={lan} introduced={introduced}"
            );
            assert_eq!(known_asked.get(), fail_closed, "known_peer asked only while failing closed");
            assert_eq!(
                introduced_asked.get(),
                (fail_closed && !known) || (!fail_closed && blocked && lan),
                "session_introduced asked only when it decides \
                 (blocked={blocked} fail_closed={fail_closed} known={known} lan={lan})"
            );
        }
    }

    /// Every precondition a punch needs, each removed in turn. With relay
    /// deliberately excluded, an `Err` here is a genuine dead end for the
    /// pair. The reason is asserted too, because only `SymmetricNat` is shown
    /// to the user — misreporting a transient cause as the permanent one would
    /// tell someone to forward a port they don't need to.
    #[test]
    fn punch_requires_quic_rendezvous_external_addr_and_a_non_symmetric_nat() {
        let addr: SocketAddr = "93.184.216.34:4670".parse().unwrap();
        let ok = |quic, nat, ext, registered| {
            friend_xfer_transport_choice(true, 4662, quic, nat, ext, registered)
        };

        assert!(ok(
            Some(4670),
            ember::nat::NatType::RestrictedCone,
            Some(addr),
            true
        )
        .is_ok());
        // No QUIC endpoint bound yet.
        assert_eq!(
            ok(None, ember::nat::NatType::RestrictedCone, Some(addr), true),
            Err(NoTransportReason::NoQuicPort)
        );
        assert_eq!(
            ok(
                Some(0),
                ember::nat::NatType::RestrictedCone,
                Some(addr),
                true
            ),
            Err(NoTransportReason::NoQuicPort)
        );
        // Not discoverable, so the friend's mailbox poll would find nothing.
        assert_eq!(
            ok(
                Some(4670),
                ember::nat::NatType::RestrictedCone,
                Some(addr),
                false
            ),
            Err(NoTransportReason::NotRegistered)
        );
        // No external address to publish.
        assert_eq!(
            ok(Some(4670), ember::nat::NatType::RestrictedCone, None, true),
            Err(NoTransportReason::NoExternalAddr)
        );
        // Symmetric NAT re-maps per destination, so the port we register is not
        // the port the friend would arrive on.
        assert_eq!(
            ok(Some(4670), ember::nat::NatType::Symmetric, Some(addr), true),
            Err(NoTransportReason::SymmetricNat)
        );
    }

    fn relay_att(pubkey: u8, ip: [u8; 4], port: u16, expires: u64) -> ember::RelayAttestation {
        ember::RelayAttestation {
            ed25519_pubkey: [pubkey; 32],
            relay_ip: Ipv4Addr::from(ip),
            relay_port: port,
            expires_at_unix: expires,
            capability_bits: ember::RELAY_ATTESTATION_CAP_RELAY_V1,
            signature: [0u8; 64],
        }
    }

    /// The digest must ignore `expires_at`. Our own attestation is re-signed
    /// with a fresh expiry every time the offer is built, so a digest that
    /// covered it would change on every tick and re-send the same set to every
    /// friend forever.
    #[test]
    fn relay_offer_digest_ignores_expiry_churn() {
        let now = 1_700_000_000;
        let early = vec![relay_att(1, [8, 8, 8, 8], 4662, now + 60)];
        let renewed = vec![relay_att(1, [8, 8, 8, 8], 4662, now + 1800)];
        assert_eq!(
            relay_offer_digest(&early, now),
            relay_offer_digest(&renewed, now)
        );
    }

    /// Reordering carries no information, so it must not count as a change.
    /// A genuinely different relay must.
    #[test]
    fn relay_offer_digest_tracks_membership_not_order() {
        let now = 1_700_000_000;
        let a = relay_att(1, [8, 8, 8, 8], 4662, now + 600);
        let b = relay_att(2, [9, 9, 9, 9], 4663, now + 600);
        assert_eq!(
            relay_offer_digest(&[a.clone(), b.clone()], now),
            relay_offer_digest(&[b.clone(), a.clone()], now)
        );
        assert_ne!(
            relay_offer_digest(std::slice::from_ref(&a), now),
            relay_offer_digest(&[a, b], now)
        );
    }

    /// An unchanged set is still re-offered once per refresh bucket, so a
    /// friend's copy is renewed before its own TTL runs out.
    #[test]
    fn relay_offer_digest_rolls_over_for_periodic_refresh() {
        let now = 1_700_000_000;
        let offer = vec![relay_att(1, [8, 8, 8, 8], 4662, now + 1800)];
        assert_ne!(
            relay_offer_digest(&offer, now),
            relay_offer_digest(&offer, now + RELAY_OFFER_REFRESH_SECS)
        );
        const _: () = assert!(
            RELAY_OFFER_REFRESH_SECS < ember::RELAY_ATTESTATION_MAX_TTL_SECS,
            "a refresh must land before the friend's copy expires"
        );
    }

    /// Only the symmetric-NAT dead end is permanent, and only a permanent
    /// reason parks the source as `Unreachable`. The transient three all clear
    /// during startup, so surfacing them would train users to ignore the
    /// warning.
    #[test]
    fn only_symmetric_nat_is_reported_as_a_permanent_dead_end() {
        assert!(NoTransportReason::SymmetricNat.is_permanent());
        assert!(!NoTransportReason::NoQuicPort.is_permanent());
        assert!(!NoTransportReason::NoExternalAddr.is_permanent());
        assert!(!NoTransportReason::NotRegistered.is_permanent());
    }

    /// A symmetric NAT that is *also* still waiting on its QUIC bind must
    /// report the permanent cause, not the transient one — otherwise which
    /// message the user reads depends on startup timing.
    #[test]
    fn symmetric_nat_outranks_a_transient_precondition() {
        assert_eq!(
            friend_xfer_transport_choice(
                true,
                4662,
                None,
                ember::nat::NatType::Symmetric,
                None,
                false,
            ),
            Err(NoTransportReason::SymmetricNat)
        );
    }

    /// A punch request needs no routable address in the payload, but does need
    /// the responder's own punch machinery to be usable.
    #[test]
    fn inbound_punch_ignores_payload_address_but_requires_punch_capability() {
        let now = Instant::now();
        let request = ed2k::messages::EmberXferRequest {
            method: ed2k::messages::EmberXferMethod::Punch,
            file_hash: FILE_1,
            tcp_port: 0,
            nonce: [7; 16],
        };
        // Relay placeholder address and port 0 would both sink a connect-back.
        let placeholder: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert_eq!(
            friend_xfer_inbound_status(true, &request, placeholder, None, now, true, true),
            ed2k::messages::XFER_STATUS_ACCEPTED
        );
        assert_eq!(
            friend_xfer_inbound_status(true, &request, placeholder, None, now, true, false),
            ed2k::messages::XFER_STATUS_DECLINED_METHOD,
            "a peer that cannot punch must say so rather than accept and stall"
        );
    }

    #[test]
    fn same_file_respects_cooldown_then_retries_until_exhausted() {
        let base = Instant::now();
        let mut attempts = HashMap::new();
        attempts.insert((FRIEND_A, FILE_1), attempt("t1", [1; 16], base, 1));

        assert_eq!(
            friend_xfer_send_decision(
                true,
                &attempts,
                FRIEND_A,
                FILE_1,
                base + secs(FRIEND_XFER_COOLDOWN_SECS - 1)
            ),
            FriendXferSendDecision::Cooldown
        );
        assert_eq!(
            friend_xfer_send_decision(
                true,
                &attempts,
                FRIEND_A,
                FILE_1,
                base + secs(FRIEND_XFER_COOLDOWN_SECS)
            ),
            FriendXferSendDecision::Send {
                previous_attempts: 1
            }
        );

        // At the ceiling we stop asking and let the source fall back to the
        // ordinary dead-source path.
        attempts.insert(
            (FRIEND_A, FILE_1),
            attempt("t1", [1; 16], base, FRIEND_XFER_MAX_ATTEMPTS),
        );
        assert_eq!(
            friend_xfer_send_decision(
                true,
                &attempts,
                FRIEND_A,
                FILE_1,
                base + secs(FRIEND_XFER_COOLDOWN_SECS)
            ),
            FriendXferSendDecision::Exhausted
        );
    }

    /// The load-bearing invariant: the connect-back diversion in `upload.rs`
    /// identifies an arriving connection by Ember hash alone, so it is only
    /// unambiguous while at most one request per friend is in flight. Two live
    /// requests to one friend would let their single dial be adopted into the
    /// wrong download.
    #[test]
    fn only_one_request_per_friend_may_be_outstanding() {
        let base = Instant::now();
        let mut attempts = HashMap::new();
        attempts.insert((FRIEND_A, FILE_1), attempt("t1", [1; 16], base, 1));

        assert_eq!(
            friend_xfer_send_decision(true, &attempts, FRIEND_A, FILE_2, base + secs(1)),
            FriendXferSendDecision::AnotherOutstanding
        );

        // A different friend is unaffected: the ambiguity is per-identity.
        assert_eq!(
            friend_xfer_send_decision(true, &attempts, FRIEND_B, FILE_2, base + secs(1)),
            FriendXferSendDecision::Send {
                previous_attempts: 0
            }
        );

        // Once the first request can no longer produce a connect-back, the
        // second file is free to ask.
        assert_eq!(
            friend_xfer_send_decision(
                true,
                &attempts,
                FRIEND_A,
                FILE_2,
                base + secs(FRIEND_XFER_ATTEMPT_TIMEOUT_SECS)
            ),
            FriendXferSendDecision::Send {
                previous_attempts: 0
            }
        );
    }

    /// Exhaustive version of the invariant above, driven the way the network
    /// task actually drives it: escalations arrive one at a time, and each
    /// `Send` records its attempt before the next caller is considered.
    ///
    /// The property that matters to `upload.rs` is that a friend never has two
    /// *live* requests at once — one whose connect-back could still arrive.
    /// Note this is a sequential guarantee, not a property of a frozen map:
    /// two files can both look sendable against the same snapshot, and are kept
    /// apart only because the first one to send updates the map.
    #[test]
    fn one_friend_never_has_two_live_requests_at_once() {
        let base = Instant::now();
        let mut attempts: HashMap<([u8; 16], [u8; 16]), FriendXferAttempt> = HashMap::new();

        for offset in 0..=(FRIEND_XFER_COOLDOWN_SECS * 3) {
            let now = base + secs(offset);
            // Both downloads keep failing and keep trying to escalate.
            for (index, file) in [FILE_1, FILE_2].into_iter().enumerate() {
                if let FriendXferSendDecision::Send { previous_attempts } =
                    friend_xfer_send_decision(true, &attempts, FRIEND_A, file, now)
                {
                    attempts.insert(
                        (FRIEND_A, file),
                        attempt(
                            &format!("t{index}"),
                            [index as u8; 16],
                            now,
                            previous_attempts + 1,
                        ),
                    );
                }
            }

            let live = attempts
                .iter()
                .filter(|(key, a)| {
                    key.0 == FRIEND_A
                        && now.saturating_duration_since(a.sent_at).as_secs()
                            < FRIEND_XFER_ATTEMPT_TIMEOUT_SECS
                })
                .count();
            assert!(
                live <= 1,
                "at +{offset}s friend A had {live} live requests, so an arriving \
                 connect-back could not be matched to a file"
            );
        }
    }

    #[test]
    fn inbound_accepts_a_shared_file_from_a_routable_friend() {
        let now = Instant::now();
        assert_eq!(
            friend_xfer_inbound_status(
                true,
                &connect_back(FILE_1, 4662),
                routable_addr(),
                None,
                now,
                true,
                // A connect-back must not depend on punch capability.
                false
            ),
            ed2k::messages::XFER_STATUS_ACCEPTED
        );
    }

    /// A non-friend gets the same answer whether or not we hold the file, so the
    /// ack can't be used to probe what we share.
    #[test]
    fn inbound_from_non_friend_is_declined_without_revealing_the_file() {
        let now = Instant::now();
        let addr = routable_addr();
        let shared = friend_xfer_inbound_status(
            false,
            &connect_back(FILE_1, 4662),
            addr,
            None,
            now,
            true,
            false,
        );
        let not_shared = friend_xfer_inbound_status(
            false,
            &connect_back(FILE_1, 4662),
            addr,
            None,
            now,
            false,
            false,
        );
        assert_eq!(shared, ed2k::messages::XFER_STATUS_DECLINED_NOT_SHARED);
        assert_eq!(shared, not_shared);
    }

    /// The dial goes to the session's observed address, so a request arriving
    /// over a session with no routable address — a relay hop, or a peer on a
    /// private range — cannot be answered with a connect-back.
    #[test]
    fn inbound_requires_a_routable_address_and_nonzero_port() {
        let now = Instant::now();
        let request = connect_back(FILE_1, 4662);
        for addr in [
            "0.0.0.0:0",
            "192.168.1.20:51000",
            "127.0.0.1:51000",
            // RFC 5737 documentation space is not a real peer either.
            "198.51.100.7:51000",
        ] {
            let addr: SocketAddr = addr.parse().unwrap();
            assert_eq!(
                friend_xfer_inbound_status(true, &request, addr, None, now, true, false),
                ed2k::messages::XFER_STATUS_DECLINED_METHOD,
                "{addr} must not be dialed"
            );
        }

        assert_eq!(
            friend_xfer_inbound_status(
                true,
                &connect_back(FILE_1, 0),
                routable_addr(),
                None,
                now,
                true,
                false
            ),
            ed2k::messages::XFER_STATUS_DECLINED_METHOD,
            "port 0 must not be dialed"
        );
    }

    #[test]
    fn inbound_rate_limits_a_friend_asking_too_fast() {
        let base = Instant::now();
        let addr = routable_addr();
        let request = connect_back(FILE_1, 4662);

        assert_eq!(
            friend_xfer_inbound_status(
                true,
                &request,
                addr,
                Some(base),
                base + secs(FRIEND_XFER_INBOUND_MIN_INTERVAL_SECS - 1),
                true,
                false
            ),
            ed2k::messages::XFER_STATUS_DECLINED_RATE_LIMITED
        );
        assert_eq!(
            friend_xfer_inbound_status(
                true,
                &request,
                addr,
                Some(base),
                base + secs(FRIEND_XFER_INBOUND_MIN_INTERVAL_SECS),
                true,
                false
            ),
            ed2k::messages::XFER_STATUS_ACCEPTED
        );
    }

    /// Rate limiting is decided before the share lookup, so a friend hammering
    /// us learns only that they are being throttled.
    #[test]
    fn inbound_rate_limit_takes_precedence_over_not_shared() {
        let base = Instant::now();
        assert_eq!(
            friend_xfer_inbound_status(
                true,
                &connect_back(FILE_1, 4662),
                routable_addr(),
                Some(base),
                base + secs(1),
                false,
                false
            ),
            ed2k::messages::XFER_STATUS_DECLINED_RATE_LIMITED
        );
    }

    #[test]
    fn inbound_declines_a_file_we_do_not_share() {
        let now = Instant::now();
        assert_eq!(
            friend_xfer_inbound_status(
                true,
                &connect_back(FILE_1, 4662),
                routable_addr(),
                None,
                now,
                false,
                false
            ),
            ed2k::messages::XFER_STATUS_DECLINED_NOT_SHARED
        );
    }

    #[test]
    fn ack_nonce_matches_only_the_request_it_answers() {
        let base = Instant::now();
        let mut attempts = HashMap::new();
        attempts.insert((FRIEND_A, FILE_1), attempt("t1", [1; 16], base, 1));
        attempts.insert((FRIEND_A, FILE_2), attempt("t2", [2; 16], base, 1));
        attempts.insert((FRIEND_B, FILE_1), attempt("t3", [3; 16], base, 1));

        assert_eq!(
            find_friend_xfer_attempt(&attempts, FRIEND_A, [2; 16]),
            Some((FRIEND_A, FILE_2)),
            "the nonce must select the file it was issued for"
        );
        // A replayed or superseded nonce matches nothing.
        assert_eq!(find_friend_xfer_attempt(&attempts, FRIEND_A, [9; 16]), None);
        // Another friend's nonce must not resolve against ours, even though the
        // same file hash is in flight for both.
        assert_eq!(find_friend_xfer_attempt(&attempts, FRIEND_A, [3; 16]), None);
    }

    #[test]
    fn reconcile_drops_orphans_and_keeps_live_friend_expectations() {
        let mut map: HashMap<
            upload_server::PendingKadCallbackKey,
            Vec<upload_server::PendingKadCallbackEntry>,
        > = HashMap::new();
        let entry = |file_hash| upload_server::PendingKadCallbackEntry {
            file_hash,
            expected_tcp_port: 0,
            registered_at: 0,
            origin: None,
        };
        map.insert(
            upload_server::PendingKadCallbackKey::FriendEmber(FRIEND_A),
            vec![entry(FILE_1), entry(FILE_2)],
        );
        map.insert(
            upload_server::PendingKadCallbackKey::FriendEmber(FRIEND_B),
            vec![entry(FILE_1)],
        );

        let mut live = HashSet::new();
        live.insert((FRIEND_A, FILE_1));
        reconcile_friend_pending_callbacks(&mut map, &live);

        let a = map
            .get(&upload_server::PendingKadCallbackKey::FriendEmber(FRIEND_A))
            .expect("the live expectation must survive");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].file_hash, FILE_1);
        assert!(
            !map.contains_key(&upload_server::PendingKadCallbackKey::FriendEmber(FRIEND_B)),
            "a friend with no live request must be dropped entirely"
        );
    }

    /// The reconciliation is authoritative only for friend keys. eD2K and KAD
    /// callback expectations have their own TTL sweep and must be untouched,
    /// even when no friend request is live at all.
    #[test]
    fn reconcile_never_touches_server_or_kad_callback_keys() {
        let mut map: HashMap<
            upload_server::PendingKadCallbackKey,
            Vec<upload_server::PendingKadCallbackEntry>,
        > = HashMap::new();
        let entry = upload_server::PendingKadCallbackEntry {
            file_hash: FILE_1,
            expected_tcp_port: 4662,
            registered_at: 0,
            origin: None,
        };
        map.insert(
            upload_server::PendingKadCallbackKey::SourceIp(Ipv4Addr::new(198, 51, 100, 9)),
            vec![entry.clone()],
        );
        map.insert(
            upload_server::PendingKadCallbackKey::SourceUserHash([0xC7; 16]),
            vec![entry],
        );
        let before = map.clone();

        reconcile_friend_pending_callbacks(&mut map, &HashSet::new());

        assert_eq!(map.len(), before.len());
        for key in before.keys() {
            assert_eq!(
                map.get(key).map(|v| v.len()),
                Some(1),
                "non-friend key {key:?} must be preserved"
            );
        }
    }

    const CONNECT_BACK: FriendXferTransport = FriendXferTransport::ConnectBack { tcp_port: 4662 };
    const S1: (Ipv4Addr, u16) = (Ipv4Addr::new(203, 0, 113, 1), 4662);
    const S2: (Ipv4Addr, u16) = (Ipv4Addr::new(203, 0, 113, 2), 4662);
    const S3: (Ipv4Addr, u16) = (Ipv4Addr::new(203, 0, 113, 3), 4662);

    fn plan(
        transport: Result<FriendXferTransport, NoTransportReason>,
        attempts: &HashMap<([u8; 16], [u8; 16]), FriendXferAttempt>,
        key: ([u8; 16], [u8; 16]),
        now: Instant,
    ) -> Result<(FriendXferTransport, u32), FriendXferRequestOutcome> {
        friend_xfer_request_plan(transport, attempts, key, now)
    }

    fn source_list(source: (Ipv4Addr, u16)) -> ed2k::sources::PerFileSourceList {
        let mut pfs = ed2k::sources::PerFileSourceList::new(FILE_1, 100);
        assert!(pfs.add_source_full(source.0, source.1, 0));
        pfs
    }

    fn source_state(
        pfs: &ed2k::sources::PerFileSourceList,
        source: (Ipv4Addr, u16),
    ) -> &ed2k::sources::DownloadSourceState {
        &pfs.sources
            .iter()
            .find(|s| (s.ip, s.tcp_port) == source)
            .expect("the source is listed")
            .state
    }

    fn is_friend_connect(pfs: &ed2k::sources::PerFileSourceList, source: (Ipv4Addr, u16)) -> bool {
        matches!(source_state(pfs, source), ed2k::sources::DownloadSourceState::FriendConnect)
    }

    fn is_failed(pfs: &ed2k::sources::PerFileSourceList, source: (Ipv4Addr, u16)) -> bool {
        matches!(source_state(pfs, source), ed2k::sources::DownloadSourceState::Failed)
    }

    #[test]
    fn a_first_request_is_sent_and_recorded_against_its_method() {
        let now = Instant::now();
        let mut attempts = HashMap::new();
        let mut stats = FriendXferStats::default();
        let key = (FRIEND_A, FILE_1);

        let (transport, previous) =
            plan(Ok(CONNECT_BACK), &attempts, key, now).expect("nothing stands in the way");
        assert_eq!((transport, previous), (CONNECT_BACK, 0));
        record_friend_xfer_request(
            &mut attempts,
            &mut stats,
            key,
            FriendXferAttempt {
                transport,
                ..attempt("t1", [1; 16], now, previous + 1)
            },
        );
        assert_eq!(attempts[&key].attempts, 1);
        assert_eq!(attempts[&key].transfer_id, "t1");
        assert_eq!((stats.connect_back_requested, stats.punch_requested), (1, 0));

        let punch = FriendXferTransport::Punch { quic_port: 4672 };
        let other = (FRIEND_B, FILE_1);
        assert_eq!(plan(Ok(punch), &attempts, other, now), Ok((punch, 0)));
        record_friend_xfer_request(
            &mut attempts,
            &mut stats,
            other,
            FriendXferAttempt {
                transport: punch,
                ..attempt("t1", [2; 16], now, 1)
            },
        );
        assert_eq!((stats.connect_back_requested, stats.punch_requested), (1, 1));
    }

    /// Whether for the same file or another, a request to a friend still
    /// awaiting their answer holds the next one back without refusing it.
    #[test]
    fn a_request_in_flight_to_the_friend_reports_outstanding() {
        let now = Instant::now();
        let mut attempts = HashMap::new();
        attempts.insert((FRIEND_A, FILE_1), attempt("t1", [1; 16], now - secs(10), 1));

        assert_eq!(
            plan(Ok(CONNECT_BACK), &attempts, (FRIEND_A, FILE_1), now),
            Err(FriendXferRequestOutcome::Outstanding)
        );
        assert_eq!(
            plan(Ok(CONNECT_BACK), &attempts, (FRIEND_A, FILE_2), now),
            Err(FriendXferRequestOutcome::Outstanding)
        );
        assert_eq!(
            plan(Ok(CONNECT_BACK), &attempts, (FRIEND_B, FILE_2), now),
            Ok((CONNECT_BACK, 0)),
            "another friend is not held back"
        );
    }

    /// Past the attempt timeout nothing is in flight any more, so the cooldown
    /// and the attempt ceiling are plain refusals.
    #[test]
    fn a_cooldown_or_exhausted_request_with_nothing_in_flight_is_refused() {
        let now = Instant::now();
        let key = (FRIEND_A, FILE_1);
        let mut attempts = HashMap::new();
        attempts.insert(
            key,
            attempt("t1", [1; 16], now - secs(FRIEND_XFER_ATTEMPT_TIMEOUT_SECS), 1),
        );
        assert_eq!(
            plan(Ok(CONNECT_BACK), &attempts, key, now),
            Err(FriendXferRequestOutcome::Refused)
        );

        attempts.insert(
            key,
            attempt("t1", [1; 16], now - secs(FRIEND_XFER_COOLDOWN_SECS), 1),
        );
        assert_eq!(plan(Ok(CONNECT_BACK), &attempts, key, now), Ok((CONNECT_BACK, 1)));

        attempts.insert(
            key,
            attempt(
                "t1",
                [1; 16],
                now - secs(FRIEND_XFER_COOLDOWN_SECS),
                FRIEND_XFER_MAX_ATTEMPTS,
            ),
        );
        assert_eq!(
            plan(Ok(CONNECT_BACK), &attempts, key, now),
            Err(FriendXferRequestOutcome::Refused)
        );
    }

    /// Only a dead end the user can act on is `NoTransport`; the transient
    /// reasons clear by themselves and are ordinary refusals.
    #[test]
    fn only_a_permanent_lack_of_transport_is_reported_as_no_transport() {
        let now = Instant::now();
        let attempts = HashMap::new();
        let key = (FRIEND_A, FILE_1);
        assert_eq!(
            plan(Err(NoTransportReason::SymmetricNat), &attempts, key, now),
            Err(FriendXferRequestOutcome::NoTransport(NoTransportReason::SymmetricNat))
        );
        for transient in [
            NoTransportReason::NoQuicPort,
            NoTransportReason::NoExternalAddr,
            NoTransportReason::NotRegistered,
        ] {
            assert_eq!(
                plan(Err(transient), &attempts, key, now),
                Err(FriendXferRequestOutcome::Refused),
                "{transient:?}"
            );
        }
    }

    #[test]
    fn a_friend_transfer_only_source_is_parked_by_the_request_outcome() {
        for (outcome, unreachable, waits) in [
            (FriendXferRequestOutcome::Sent, false, false),
            (FriendXferRequestOutcome::Outstanding, false, true),
            (
                FriendXferRequestOutcome::NoTransport(NoTransportReason::SymmetricNat),
                true,
                false,
            ),
            (FriendXferRequestOutcome::Refused, true, false),
        ] {
            let mut waiting = HashMap::new();
            assert_eq!(
                friend_transfer_only_parking(&mut waiting, outcome, FRIEND_A, "t1"),
                unreachable,
                "{outcome:?}"
            );
            assert_eq!(
                waiting.get(&FRIEND_A).is_some_and(|w| w.contains("t1")),
                waits,
                "{outcome:?}"
            );

            let mut pfs = source_list(S1);
            park_in_source_list(&mut pfs, S1.0, S1.1, unreachable);
            let parked_as_expected = if unreachable {
                matches!(source_state(&pfs, S1), ed2k::sources::DownloadSourceState::Unreachable)
            } else {
                is_friend_connect(&pfs, S1)
            };
            assert!(parked_as_expected, "{outcome:?}: {:?}", source_state(&pfs, S1));
        }
    }

    /// Every download waiting on a friend joins the one set; it is released
    /// whole by the request's ending and not by another friend's.
    #[test]
    fn waiting_sources_are_released_once_and_only_by_their_friend() {
        let mut waiting = HashMap::new();
        let outstanding = FriendXferRequestOutcome::Outstanding;
        friend_transfer_only_parking(&mut waiting, outstanding, FRIEND_A, "t2");
        friend_transfer_only_parking(&mut waiting, outstanding, FRIEND_A, "t3");
        friend_transfer_only_parking(&mut waiting, outstanding, FRIEND_A, "t2");
        friend_transfer_only_parking(&mut waiting, outstanding, FRIEND_B, "t4");

        assert!(take_sources_waiting_on_friend(&mut waiting, [0xCC; 16]).is_empty());
        let released = take_sources_waiting_on_friend(&mut waiting, FRIEND_A);
        assert_eq!(released, HashSet::from(["t2".to_string(), "t3".to_string()]));
        assert!(
            take_sources_waiting_on_friend(&mut waiting, FRIEND_A).is_empty(),
            "a second ending for the same request releases nothing"
        );
        assert!(waiting.contains_key(&FRIEND_B));
    }

    /// Downloads behind a request to `FRIEND_A`: `t1` asked for `FILE_1` and
    /// `t2` waits its turn. `t3` waits on `FRIEND_B` and must be untouched by
    /// whatever ends `FRIEND_A`'s request.
    struct Parked {
        attempts: HashMap<([u8; 16], [u8; 16]), FriendXferAttempt>,
        waiting: HashMap<[u8; 16], HashSet<String>>,
        sources: HashMap<String, ed2k::sources::PerFileSourceList>,
    }

    const NONCE: [u8; 16] = [0x4E; 16];

    fn parked(sent_at: Instant) -> Parked {
        let mut attempts = HashMap::new();
        attempts.insert((FRIEND_A, FILE_1), attempt("t1", NONCE, sent_at, 1));
        let mut waiting = HashMap::new();
        let mut sources = HashMap::new();
        for (tid, source, friend, outcome) in [
            ("t1", S1, FRIEND_A, FriendXferRequestOutcome::Sent),
            ("t2", S2, FRIEND_A, FriendXferRequestOutcome::Outstanding),
            ("t3", S3, FRIEND_B, FriendXferRequestOutcome::Outstanding),
        ] {
            let mut pfs = source_list(source);
            let unreachable = friend_transfer_only_parking(&mut waiting, outcome, friend, tid);
            park_in_source_list(&mut pfs, source.0, source.1, unreachable);
            sources.insert(tid.to_string(), pfs);
        }
        Parked {
            attempts,
            waiting,
            sources,
        }
    }

    impl Parked {
        /// What every ending does once its own bookkeeping is done:
        /// `release_friend_connect_sources` for the request's own download
        /// when it has one to release, then `release_sources_waiting_on_friend`.
        fn end(&mut self, own: Option<&str>, friend: [u8; 16]) -> Vec<(Ipv4Addr, u16)> {
            let now = Instant::now();
            let mut released = Vec::new();
            if let Some(pfs) = own.and_then(|tid| self.sources.get_mut(tid)) {
                released.extend(release_friend_connect_in_list(pfs, now));
            }
            for tid in take_sources_waiting_on_friend(&mut self.waiting, friend) {
                if let Some(pfs) = self.sources.get_mut(&tid) {
                    released.extend(release_friend_connect_in_list(pfs, now));
                }
            }
            released
        }

        fn assert_only_friend_b_still_waits(&self) {
            assert!(!self.waiting.contains_key(&FRIEND_A));
            assert!(self.waiting[&FRIEND_B].contains("t3"));
            assert!(is_friend_connect(&self.sources["t3"], S3));
        }
    }

    #[test]
    fn a_decline_releases_the_asking_and_the_waiting_downloads() {
        let mut p = parked(Instant::now());
        // `handle_friend_transfer_ack` on a decline status.
        let key = find_friend_xfer_attempt(&p.attempts, FRIEND_A, NONCE).expect("live");
        p.attempts.remove(&key);
        let released = p.end(Some("t1"), FRIEND_A);

        assert_eq!(released.len(), 2);
        assert!(is_failed(&p.sources["t1"], S1));
        assert!(is_failed(&p.sources["t2"], S2));
        p.assert_only_friend_b_still_waits();
    }

    #[test]
    fn an_abandoned_punch_releases_the_waiting_downloads() {
        let mut p = parked(Instant::now());
        let (key, tid) =
            take_abandoned_friend_xfer_attempt(&mut p.attempts, FRIEND_A, NONCE, Instant::now())
                .expect("an attempt inside its timeout is abandoned");
        assert_eq!((key, tid.as_str()), ((FRIEND_A, FILE_1), "t1"));
        assert!(p.attempts.is_empty());
        p.end(Some(&tid), FRIEND_A);

        assert!(is_failed(&p.sources["t1"], S1));
        assert!(is_failed(&p.sources["t2"], S2));
        p.assert_only_friend_b_still_waits();
    }

    /// The timeout sweep has already released everything and keeps the record
    /// for its retry count and cooldown; a late punch failure must touch
    /// neither, nor free downloads that have parked behind the friend since.
    #[test]
    fn abandoning_a_timed_out_attempt_changes_nothing() {
        let sent_at = Instant::now() - secs(FRIEND_XFER_ATTEMPT_TIMEOUT_SECS);
        let mut p = parked(sent_at);
        assert_eq!(
            take_abandoned_friend_xfer_attempt(&mut p.attempts, FRIEND_A, NONCE, Instant::now()),
            None
        );
        assert!(p.attempts.contains_key(&(FRIEND_A, FILE_1)));
        assert!(p.waiting[&FRIEND_A].contains("t2"));
        assert!(is_friend_connect(&p.sources["t2"], S2));

        assert_eq!(
            take_abandoned_friend_xfer_attempt(&mut p.attempts, FRIEND_A, [0; 16], Instant::now()),
            None,
            "nor does a nonce from no live attempt"
        );
    }

    /// The friend's stream was adopted, so the asking download's source is
    /// already transferring: only the downloads waiting their turn move.
    #[test]
    fn a_connection_releases_the_waiting_downloads_and_leaves_the_live_one() {
        let mut p = parked(Instant::now());
        p.sources.get_mut("t1").unwrap().set_downloading(S1.0, S1.1, None);
        // `kad_callback` on a stream from the friend diversion.
        p.attempts.remove(&(FRIEND_A, FILE_1));
        let released = p.end(Some("t1"), FRIEND_A);

        assert_eq!(released, vec![S2]);
        assert!(matches!(
            source_state(&p.sources["t1"], S1),
            ed2k::sources::DownloadSourceState::Downloading
        ));
        assert!(is_failed(&p.sources["t2"], S2));
        p.assert_only_friend_b_still_waits();
    }

    /// The sweep releases the asking download only while it still has a
    /// parked source, but the waiting ones always, and keeps the attempt.
    #[test]
    fn a_timeout_releases_the_waiting_downloads_even_with_none_of_its_own_parked() {
        let mut p = parked(Instant::now() - secs(FRIEND_XFER_ATTEMPT_TIMEOUT_SECS));
        p.sources.get_mut("t1").unwrap().clear_friend_connect(S1.0, S1.1, None);
        let own_parked = !p.sources["t1"]
            .friend_connect_sources(Instant::now())
            .is_empty();
        assert!(!own_parked);
        let released = p.end(None, FRIEND_A);

        assert_eq!(released, vec![S2]);
        assert!(p.attempts.contains_key(&(FRIEND_A, FILE_1)));
        p.assert_only_friend_b_still_waits();
    }

    /// A timed-out request to a friend does not stand in for a live one: the
    /// downloads parked behind the request still in flight keep waiting.
    #[test]
    fn a_stale_timeout_does_not_release_downloads_behind_a_live_request() {
        let now = Instant::now();
        let mut attempts = HashMap::new();
        attempts.insert(
            (FRIEND_A, FILE_1),
            attempt("t1", [1; 16], now - secs(FRIEND_XFER_ATTEMPT_TIMEOUT_SECS + 5), 1),
        );
        assert!(!friend_has_live_request(&attempts, FRIEND_A, now), "only a stale one so far");
        attempts.insert((FRIEND_A, FILE_2), attempt("t2", [2; 16], now - secs(5), 1));
        assert!(friend_has_live_request(&attempts, FRIEND_A, now));
        assert!(
            !friend_has_live_request(&attempts, FRIEND_B, now),
            "another friend's requests say nothing about this one"
        );
        assert!(!friend_has_live_request(
            &attempts,
            FRIEND_A,
            now + secs(FRIEND_XFER_ATTEMPT_TIMEOUT_SECS)
        ));
    }

    /// Only `FriendConnect` is released: a source parked `Unreachable` has
    /// nothing outstanding and keeps its state.
    #[test]
    fn releasing_leaves_an_unreachable_source_alone() {
        let mut pfs = source_list(S1);
        park_in_source_list(&mut pfs, S1.0, S1.1, true);
        assert!(release_friend_connect_in_list(&mut pfs, Instant::now()).is_empty());
        assert!(matches!(
            source_state(&pfs, S1),
            ed2k::sources::DownloadSourceState::Unreachable
        ));
    }
}
