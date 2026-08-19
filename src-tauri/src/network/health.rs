//! Plain result and diagnostic-snapshot types for the network task.
//!
//! What belongs here: the inert data carriers that background jobs spawned by
//! `start_network` send back over their result channels, plus the counter
//! snapshots the health heartbeats diff against. They are pure data — no
//! methods, no I/O, and no reach into `NetworkState`.
//!
//! What does not belong here: the spawners, the timer arms that consume these
//! values, and anything that interprets them. Those stay next to the subsystem
//! they drive, because interpreting a result needs the state the result is
//! about.

use std::net::SocketAddr;

use super::ed2k::server::{Ed2kServerConnection, ServerSession};
use super::{ember, rendezvous, upnp};

pub(crate) struct ServerConnectResult {
    pub(crate) addr: SocketAddr,
    pub(crate) ip: String,
    pub(crate) port: u16,
    /// Our own TCP port as sent in this attempt's `OP_LOGINREQUEST` — NOT
    /// the server's `port` above. Recorded into
    /// `NetworkState::server_login_tcp_port` on success so a later
    /// STUN-confirmed remap can detect it needs a reconnect.
    pub(crate) login_tcp_port: u16,
    pub(crate) result: Result<(Ed2kServerConnection, ServerSession), String>,
}

pub(crate) struct KnownMetSaveResult {
    pub(crate) generation: u64,
    pub(crate) result: anyhow::Result<bool>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PeriodicSaveJob {
    Stats,
    Reputation,
    Known2,
    Nodes,
}

pub(crate) struct PeriodicSaveResult {
    pub(crate) job: PeriodicSaveJob,
    pub(crate) result: Result<(), String>,
}

pub(crate) struct SpamSaveResult {
    pub(crate) result: Result<(), String>,
}

pub(crate) struct UpnpMaintainResult {
    pub(crate) revision: u64,
    pub(crate) mappings: upnp::UpnpMappings,
    pub(crate) mapped: bool,
}

pub(crate) struct RendezvousRegisterResult {
    pub(crate) generation: u64,
    pub(crate) initial: bool,
    pub(crate) result: Result<rendezvous::RegistrationOutcome, String>,
}

pub(crate) struct FriendRelayTicketPollResult {
    pub(crate) result: Result<rendezvous::FriendRelayTicketPollPage, String>,
}

pub(crate) struct NatProbeResult {
    pub(crate) generation: u64,
    pub(crate) reason: &'static str,
    pub(crate) info: ember::nat::NatInfo,
}

pub(crate) struct UdpMappingKeepaliveResult {
    pub(crate) generation: u64,
    pub(crate) mapped: Option<SocketAddr>,
}

pub(crate) struct TcpMappingKeepaliveResult {
    pub(crate) generation: u64,
    pub(crate) hold_ok: bool,
    pub(crate) mapped: Option<SocketAddr>,
}

/// Outcome of one TCP STUN observation against the current TCP
/// remap-candidate tracking state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpPortConfirmation {
    /// Updated `stun_ka_tcp_candidate_port` (cleared once confirmed).
    pub(crate) candidate_port: Option<u16>,
    /// Updated `stun_ka_tcp_stable_hits` (reset once confirmed).
    pub(crate) stable_hits: u8,
    /// The port that should now be advertised, if this observation just
    /// became trustworthy (immediately or via the stability streak).
    pub(crate) confirmed_port: Option<u16>,
}

#[derive(Debug, Default)]
pub(crate) struct ActiveSourceInjectionStats {
    pub(crate) matched_transfers: usize,
    pub(crate) injected: usize,
    pub(crate) persisted: usize,
    pub(crate) dropped_full: usize,
    pub(crate) dropped_closed: usize,
    pub(crate) overflowed: usize,
}

/// Snapshot of the publish-ack diagnostic counters at a given time.
/// Used by the `publish_health_timer` arm to print **deltas** since
/// the last beat instead of monotonic totals — without this the
/// numbers look identical heartbeat after heartbeat once the system
/// has been running a while, and you can't tell whether the pipeline
/// is currently flowing or stuck.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PublishHealthSnapshot {
    pub(crate) confirmed: u32,
    pub(crate) pending: usize,
    pub(crate) plain_seen: u64,
    pub(crate) obf_decoded: u64,
    pub(crate) obf_total: u64,
    pub(crate) wire: u64,
    pub(crate) received: u64,
    pub(crate) unmatched: u64,
}

/// Snapshot of the UDP source-discovery diagnostic counters at a given
/// time. Same delta-style logging pattern as `PublishHealthSnapshot`:
/// the heartbeat arm only fires the log line when at least one counter
/// moved since the last beat. Lets the user verify "is UDP source
/// discovery happening at all" without flipping to debug logging.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct UdpDiscoveryHealthSnapshot {
    pub(crate) sent: u64,
    pub(crate) send_errs: u64,
    pub(crate) replies: u64,
    pub(crate) sources_found: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceInjectionResult {
    Injected,
    Full,
    Closed,
}
