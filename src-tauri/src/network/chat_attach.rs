//! Chat attachments, as the network loop sees them.
//!
//! [`super::ember::attach`] is the wire format and the capability,
//! [`super::ember::attach_stream`] moves the bytes, and the `chat_attachments`
//! table is the grant. This is the part that ties them to people: it sends an
//! offer, answers one, decides what to fetch without asking, runs the fetch,
//! and tells the UI what happened.
//!
//! Every status a row can hold, and who moves it there:
//!
//! | status        | side     | meaning                                         |
//! |---------------|----------|-------------------------------------------------|
//! | `offered`     | sender   | sent, nobody has answered                       |
//! | `awaiting`    | receiver | offered to us, waiting on the user              |
//! | `accepted`    | sender   | the friend said yes and will dial               |
//! | `active`      | both     | bytes are moving                                |
//! | `complete`    | both     | sender: the friend acknowledged every byte; receiver: verified and in `Chat Files` |
//! | `declined`, `too_large`, `busy`, `not_allowed` | sender | the friend's answer was no |
//! | `cancelled`   | both     | someone pressed cancel                          |
//! | `unreachable` | both     | the recipient never got a direct connection to the sender |
//! | `source_gone` | both     | the sender's file changed or went away before it was read |
//! | `failed`      | both     | it could not be finished                        |
//! | `expired`     | both     | nobody answered in time, or a restart stranded it |

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::Emitter;
use tracing::{debug, info, warn};

use super::ed2k::messages::{
    build_ember_ext_frame, EMBER_EXT_ATTACH_CANCEL, EMBER_EXT_ATTACH_OFFER, EMBER_EXT_ATTACH_REPLY,
};
use super::ember::attach::{
    self, AttachCancel, AttachOffer, AttachReply, AttachStreamStatus, ATTACH_GRANT_TTL_SECS,
    ATTACH_OFFER_TTL_SECS,
};
use super::ember::attach_stream::{self, FetchError};
use super::NetworkState;
use crate::commands::errors::{coded, coded_ctx};
use crate::storage::database::{ChatAttachmentRow, Database};
use crate::types::AppSettings;

/// Frontend event carrying one attachment's current state.
pub(crate) const ATTACH_EVENT: &str = "ember:attach-update";

/// Receives running at once. Past this an auto-accept leaves the offer waiting
/// for the user rather than refusing it, and an explicit accept is told to wait.
const MAX_ACTIVE_FETCHES: usize = 4;

/// Of those, how many may be from one friend. A sender that accepts streams
/// and never answers holds each slot for a full status wait, so without this
/// one friend could hold every receive the user has.
const MAX_ACTIVE_FETCHES_PER_FRIEND: usize = 2;

/// Offers from one friend waiting on an answer at once. A friend who keeps
/// offering without the user answering gets "busy" rather than a growing list.
const MAX_PENDING_PER_FRIEND: usize = 8;

/// How often a moving transfer tells the UI where it is.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);

/// Dials a receive makes before it gives up. A dropped connection resumes from
/// the last verified chunk, so a retry costs a round trip, not the file.
const FETCH_ATTEMPTS: u32 = 4;

/// How long one QUIC dial may take before it counts as a failed attempt.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a sender keeps its punching dial alive. It only has to overlap the
/// recipient's own dial, which starts the moment the accept is sent.
const PUNCH_WINDOW: Duration = Duration::from_secs(8);

/// Window the auto-accept budget is measured over.
const AUTO_ACCEPT_WINDOW_SECS: i64 = 60 * 60;

/// Files one friend may have fetched without asking inside the window.
const AUTO_ACCEPT_MAX_FILES: usize = 20;

/// Bytes one friend may have fetched without asking inside the window. Never
/// less than one file at the user's own ceiling, so raising the ceiling is not
/// silently cancelled by this.
const AUTO_ACCEPT_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Free space an accepted attachment must leave beyond its own size, so taking
/// it up does not run the volume to its last byte.
const ATTACH_DISK_HEADROOM: u64 = 64 * 1024 * 1024;

/// Where finished attachments land, beside `Downloads` and `Temp` under the
/// download folder. A folder of its own because these are files people were
/// handed in a conversation, not files they went looking for — and so they can
/// find them again.
pub(crate) const CHAT_FILES_DIR: &str = "Chat Files";

/// One attachment as the UI draws it.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChatAttachmentInfo {
    pub xfer_id: String,
    pub user_hash: String,
    pub direction: String,
    pub name: String,
    pub size: u64,
    pub transferred: u64,
    pub status: String,
    pub created_at: i64,
    /// A received file that finished and can be opened. Never true on the
    /// sending side: our own copy's path is not something the UI needs.
    pub has_file: bool,
}

impl ChatAttachmentInfo {
    pub(crate) fn from_row(row: &ChatAttachmentRow) -> Self {
        Self {
            xfer_id: row.xfer_id.clone(),
            user_hash: row.friend_hash.clone(),
            direction: row.direction.clone(),
            name: row.file_name.clone(),
            size: row.file_size,
            transferred: if row.status == "complete" {
                row.file_size
            } else {
                row.transferred.min(row.file_size)
            },
            status: row.status.clone(),
            created_at: row.created_at,
            has_file: row.direction == "received"
                && row.status == "complete"
                && row.dest_path.is_some(),
        }
    }
}

pub(crate) fn emit_row(app: &tauri::AppHandle, row: &ChatAttachmentRow) {
    let _ = app.emit(ATTACH_EVENT, ChatAttachmentInfo::from_row(row));
}

fn emit_by_id(app: &tauri::AppHandle, db: &Database, xfer_hex: &str) {
    if let Some(row) = db.chat_attachment(xfer_hex) {
        emit_row(app, &row);
    }
}

/// A progress tick, built from a snapshot. The stored status is still read
/// first: a cancel can land between two chunks, and a tick after it would set
/// a stopped bubble moving again.
fn emit_progress(app: &tauri::AppHandle, db: &Database, row: &ChatAttachmentRow, transferred: u64) {
    if db
        .chat_attachment(&row.xfer_id)
        .is_none_or(|current| is_terminal(&current.status))
    {
        return;
    }
    let mut info = ChatAttachmentInfo::from_row(row);
    info.transferred = transferred.min(row.file_size);
    info.status = "active".into();
    let _ = app.emit(ATTACH_EVENT, info);
}

/// Statuses nothing moves a row out of.
fn is_terminal(status: &str) -> bool {
    matches!(
        status,
        "complete"
            | "declined"
            | "too_large"
            | "busy"
            | "not_allowed"
            | "cancelled"
            | "unreachable"
            | "source_gone"
            | "failed"
            | "expired"
    )
}

/// Part file for a receive, under `Temp` like every other download's.
fn part_file_name(xfer_id: &[u8; 16]) -> String {
    format!("ember-attach-{}.part", hex::encode(xfer_id))
}

/// An address we are willing to dial for a friend's attachment.
///
/// The IP is the one the friend session is actually connected to — the friend
/// names only the port — so this is not an arbitrary target. It still refuses
/// the addresses that are never a peer, and folds an IPv4-mapped IPv6 address
/// back to IPv4, because the QUIC endpoint is bound on IPv4.
pub(super) fn dial_target(ip: IpAddr, port: u16) -> Option<SocketAddr> {
    let ip = match ip {
        IpAddr::V6(v6) => IpAddr::V4(v6.to_ipv4_mapped()?),
        v4 => v4,
    };
    let IpAddr::V4(v4) = ip else {
        return None;
    };
    if port == 0 || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
        return None;
    }
    Some(SocketAddr::new(ip, port))
}

/// A friend at this address reaches us without crossing our NAT: on the same
/// network, on this machine, or across a VPN mesh (100.64/10, which Tailscale
/// uses). Behind a CGNAT the address is not ours either, and neither port is
/// right there, so treating it as direct costs nothing.
pub(super) fn reached_directly(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || crate::security::is_lan_or_cgnat_v4(v4),
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback() || first & 0xFE00 == 0xFC00 || first & 0xFFC0 == 0xFE80
        }
    }
}

/// The QUIC port to name to a friend connected from `peer`.
///
/// The public port STUN reports is the one our NAT maps the endpoint to, and it
/// only exists on the far side of the router. A friend on our own network dials
/// our local address, where the endpoint listens on its own port; naming the
/// mapped one there sent every dial of a LAN transfer to a port nothing
/// listened on, until the receiver gave up.
pub(super) fn quic_port_for(state: &NetworkState, peer: Option<SocketAddr>) -> Option<u16> {
    choose_quic_port(state.quic_port, super::advertised_quic_port(state), peer)
}

fn choose_quic_port(
    local: Option<u16>,
    advertised: Option<u16>,
    peer: Option<SocketAddr>,
) -> Option<u16> {
    match local.filter(|p| *p != 0) {
        Some(port) if peer.is_some_and(|addr| reached_directly(addr.ip())) => Some(port),
        _ => advertised,
    }
}

/// What accepting an offer needs, held from the offer until it is answered.
pub(crate) struct InboundAttach {
    friend: [u8; 16],
    peer_pubkey: [u8; 32],
    /// `None` when the offer came over a relayed session.
    peer_addr: Option<SocketAddr>,
    offer: AttachOffer,
    /// Sanitized: what the file will be called on disk.
    name: String,
    received_at: i64,
}

async fn send_ext(
    state: &NetworkState,
    friend: &[u8; 16],
    sub_type: u8,
    body: &[u8],
) -> Result<(), String> {
    let sessions = state.ember_sessions.read().await;
    let Some(session) = sessions
        .get(friend)
        .filter(|h| h.is_fresh() && h.is_secure_v2())
    else {
        return Err(coded(
            "peers_attach_offline",
            "Your friend is offline. Files can only be sent while you are both connected.",
        ));
    };
    session
        .tx
        .try_send(build_ember_ext_frame(sub_type, body))
        .map_err(|_| {
            coded(
                "peers_attach_offline",
                "Your friend is offline. Files can only be sent while you are both connected.",
            )
        })
}

fn relayed() -> String {
    coded(
        "peers_attach_relayed",
        "You and your friend are only connected through a relay, and files need a direct connection. Try again later.",
    )
}

/// Everything that has to hold before a file can be offered, and our public
/// QUIC port when it does. Asked once before the picker opens, so the user is
/// not made to choose and hash a file that cannot go anywhere, and again with
/// the offer itself, since the session can change in between.
///
/// A relayed session is refused rather than tried. The recipient dials the
/// address the session came from, and a relay leaves none — or only the one
/// the session already failed to reach directly — so the offer would sit
/// through every retry and end as a failure nobody could explain.
pub(super) async fn offer_preflight(
    state: &NetworkState,
    settings: &AppSettings,
    friend: &[u8; 16],
) -> Result<u16, String> {
    if settings.friend_chat_disabled {
        return Err(coded(
            "peers_attach_disabled",
            "Chatting with friends is turned off in Settings",
        ));
    }
    if quic_endpoint(state).is_none() {
        return Err(unavailable());
    }
    let sessions = state.ember_sessions.read().await;
    let Some(session) = sessions
        .get(friend)
        .filter(|h| h.is_fresh() && h.is_secure_v2())
    else {
        return Err(coded(
            "peers_attach_offline",
            "Your friend is offline. Files can only be sent while you are both connected.",
        ));
    };
    if session.is_relayed() {
        return Err(relayed());
    }
    quic_port_for(state, session.peer_addr()).ok_or_else(unavailable)
}

async fn session_pubkey(state: &NetworkState, friend: &[u8; 16]) -> Option<[u8; 32]> {
    state
        .ember_sessions
        .read()
        .await
        .get(friend)
        .filter(|h| h.is_secure_v2())
        .map(|h| h.peer_ember_pubkey())
}

async fn session_tx(
    state: &NetworkState,
    friend: &[u8; 16],
) -> Option<tokio::sync::mpsc::Sender<Vec<u8>>> {
    state
        .ember_sessions
        .read()
        .await
        .get(friend)
        .filter(|h| h.is_secure_v2())
        .map(|h| h.tx.clone())
}

pub(super) fn quic_endpoint(state: &NetworkState) -> Option<Arc<quinn::Endpoint>> {
    state
        .connection_broker
        .as_ref()
        .and_then(|broker| broker.quic_endpoint())
        .cloned()
}

fn running_fetches(state: &mut NetworkState) -> usize {
    state.attach_fetches.retain(|_, handle| !handle.is_finished());
    state.attach_fetches.len()
}

/// Whether another receive may start from `friend`. The running set is keyed
/// by transfer, so the friend behind each comes from its row — at most
/// [`MAX_ACTIVE_FETCHES`] point reads, on an accept.
fn fetch_slot_free(state: &mut NetworkState, db: &Database, friend: &[u8; 16]) -> bool {
    let total = running_fetches(state);
    let friend_hex = hex::encode(friend);
    let theirs = state
        .attach_fetches
        .keys()
        .filter(|id| {
            db.chat_attachment(&hex::encode(id))
                .is_some_and(|row| row.friend_hash.eq_ignore_ascii_case(&friend_hex))
        })
        .count();
    fetch_slots_allow(total, theirs)
}

/// How long the next stream of a fetch waits for the sender's status byte,
/// given how long the fetch's earlier streams actually waited for theirs.
fn next_status_wait(waited: Duration) -> Duration {
    attach_stream::ATTACH_STATUS_TIMEOUT
        .saturating_sub(waited)
        .max(attach_stream::ATTACH_RETRY_STATUS_TIMEOUT)
}

fn fetch_slots_allow(total: usize, from_friend: usize) -> bool {
    total < MAX_ACTIVE_FETCHES && from_friend < MAX_ACTIVE_FETCHES_PER_FRIEND
}

fn unavailable() -> String {
    coded(
        "peers_attach_unavailable",
        "Direct connections are not ready yet. Try again in a moment.",
    )
}

fn not_found() -> String {
    coded(
        "peers_attach_not_found",
        "That file transfer is no longer running",
    )
}

// --- Sending -----------------------------------------------------------------

/// Record the grant for a file we are offering, then send the offer.
///
/// The grant is written first on purpose. A recipient under its auto-accept
/// ceiling answers and dials within milliseconds of the offer landing, and the
/// stream it opens is refused unless the row already exists.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_offer(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    settings: &AppSettings,
    friend: [u8; 16],
    xfer_id: [u8; 16],
    path: PathBuf,
    name: String,
    size: u64,
    root: [u8; 32],
) -> Result<ChatAttachmentInfo, String> {
    let quic_port = offer_preflight(state, settings, &friend).await?;
    let offer = AttachOffer {
        xfer_id,
        size,
        root,
        quic_port,
        name: name.clone(),
    };
    let body = attach::encode_attach_offer(&offer).ok_or_else(|| {
        coded_ctx(
            "peers_attach_failed",
            "Could not send that file",
            "the file name or size cannot be offered",
        )
    })?;

    let xfer_hex = hex::encode(xfer_id);
    let now = chrono::Utc::now().timestamp();
    let path_str = path.to_string_lossy().into_owned();
    db.upsert_chat_attachment(
        &xfer_hex,
        &hex::encode(friend),
        "sent",
        &name,
        size,
        &hex::encode(root),
        Some(&path_str),
        "offered",
        now,
        now + ATTACH_OFFER_TTL_SECS,
    )
    .map_err(|e| coded_ctx("peers_attach_failed", "Could not send that file", e))?;

    if let Err(e) = send_ext(state, &friend, EMBER_EXT_ATTACH_OFFER, &body).await {
        // The session dropped between the check above and the send. Retire the
        // grant rather than leave a readable path nobody was told about.
        let _ = db.set_chat_attachment_status(&xfer_hex, "failed", None, None);
        emit_by_id(app, db, &xfer_hex);
        return Err(e);
    }
    let row = db.chat_attachment(&xfer_hex).ok_or_else(not_found)?;
    emit_row(app, &row);
    info!(
        "Chat attachment: offered {} ({size} bytes) to {}",
        crate::security::short_hash(&friend),
        xfer_hex
    );
    Ok(ChatAttachmentInfo::from_row(&row))
}

/// The friend answered an offer we made.
#[allow(clippy::too_many_arguments)]
pub(super) async fn on_reply(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    friend: [u8; 16],
    xfer_id: [u8; 16],
    reply: AttachReply,
    quic_port: Option<u16>,
    peer_addr: Option<SocketAddr>,
) {
    let xfer_hex = hex::encode(xfer_id);
    let Some(row) = db.chat_attachment(&xfer_hex) else {
        return;
    };
    // Only the friend it was offered to may answer it, and only once.
    if row.direction != "sent" || row.friend_hash != hex::encode(friend) {
        return;
    }
    if reply.is_accept() {
        // The accept can arrive after the stream has already started — the
        // recipient dials the moment it sends the accept — so `active` is as
        // valid a starting point as `offered`. The expiry still has to move:
        // the offer's short lifetime is for "nobody answered", and a retry after
        // it would otherwise be refused mid-transfer.
        if !matches!(row.status.as_str(), "offered" | "accepted" | "active") {
            return;
        }
        let now = chrono::Utc::now().timestamp();
        let Some(expires_at) = db.chat_attachment_expiry(&xfer_hex) else {
            return;
        };
        let Some(extend) = accept_extends_grant(row.created_at, expires_at, now) else {
            return;
        };
        if extend {
            let _ = db.set_chat_attachment_expiry(&xfer_hex, now + ATTACH_GRANT_TTL_SECS);
        }
        if row.status == "offered" {
            let _ = db.set_chat_attachment_status(&xfer_hex, "accepted", None, None);
            // Their dial follows the accept at once, and its first stream
            // waits on this tree before it hears a byte.
            if let Some((path, _, _)) = db.chat_attachment_grant(&xfer_hex, &row.friend_hash, now) {
                tokio::task::spawn_blocking(move || {
                    attach_stream::prewarm_attachment_hash(std::path::Path::new(&path));
                });
            }
        }
        emit_by_id(app, db, &xfer_hex);
        if let (Some(port), Some(endpoint), Some(addr)) = (quic_port, quic_endpoint(state), peer_addr) {
            if let Some(target) = dial_target(addr.ip(), port) {
                spawn_punch(endpoint, state.local_ed25519_seed, friend, target);
            }
        }
        return;
    }
    if row.status != "offered" {
        return;
    }
    let status = match reply {
        AttachReply::Accept => unreachable!("handled above"),
        AttachReply::Decline => "declined",
        AttachReply::TooLarge => "too_large",
        AttachReply::Busy => "busy",
        AttachReply::NotAllowed => "not_allowed",
    };
    let _ = db.set_chat_attachment_status(&xfer_hex, status, None, None);
    emit_by_id(app, db, &xfer_hex);
}

/// What an accept may do to a grant: `None` once it has lapsed — a late accept
/// is not a way back into an offer nobody answered — and otherwise whether it
/// still carries the offer's short lifetime and should move to the grant's.
/// Once moved it stays put, so a friend repeating the accept cannot keep a
/// path readable indefinitely.
fn accept_extends_grant(created_at: i64, expires_at: i64, now: i64) -> Option<bool> {
    if expires_at <= now {
        return None;
    }
    Some(expires_at <= created_at + ATTACH_OFFER_TTL_SECS)
}

/// Dial the recipient while it dials us, so our NAT has an outbound mapping for
/// its packets to land in.
///
/// A port-restricted NAT only admits inbound traffic from an address it has
/// already sent to. The recipient dials our advertised port, and without this
/// its first packets are dropped for having no mapping; with it, both NATs see
/// outbound traffic toward the other within the same few seconds, which is the
/// simultaneous open hole punching depends on. QUIC retransmits its handshake,
/// so the recipient's dial succeeds on a retry once the mapping exists.
///
/// Nothing is sent on the connection this makes. If it does complete, the
/// recipient's accept loop sees a connection with no stream and drops it.
pub(super) fn spawn_punch(
    endpoint: Arc<quinn::Endpoint>,
    seed: [u8; 32],
    friend: [u8; 16],
    target: SocketAddr,
) {
    tokio::spawn(async move {
        let Ok((cert, key)) = super::ember::quic::generate_self_signed_cert(&seed) else {
            return;
        };
        let dialled = tokio::time::timeout(
            PUNCH_WINDOW,
            super::ember::quic::connect_pinned(&endpoint, target, "ember", Some((&cert, &key, friend))),
        )
        .await;
        if let Ok(Ok(conn)) = dialled {
            conn.close(0u32.into(), b"attach punch");
        }
    });
}

/// Progress from the QUIC accept loop, where a friend is reading a file we
/// offered. Lives here so both sides describe a transfer in the same shape.
#[derive(Default)]
pub(crate) struct ServeProgress {
    row: Option<ChatAttachmentRow>,
    last_emit: Option<Instant>,
    /// Every chunk has been handed to the stream. Not the same as delivered:
    /// the caller still has to see the friend acknowledge them.
    queued_all: bool,
}

impl ServeProgress {
    /// A row the user cancelled must not be walked back to `active` or
    /// `complete` by a stream that was already running when they did.
    fn writable(status: &str) -> bool {
        matches!(status, "offered" | "accepted" | "active")
    }

    /// Record where a stream has got to. Returns false once it should stop:
    /// the grant is looked up again as the stream runs, so a cancel on either
    /// side, or a grant that lapsed, ends a transfer already in flight rather
    /// than only refusing the next one.
    pub(crate) fn note(
        &mut self,
        db: &Database,
        app: &tauri::AppHandle,
        xfer_id: &[u8; 16],
        peer_hex: &str,
        position: u64,
        size: u64,
    ) -> bool {
        let xfer_hex = hex::encode(xfer_id);
        if self.row.is_none() {
            let Some(row) = db.chat_attachment(&xfer_hex) else {
                return false;
            };
            if Self::writable(&row.status) {
                let _ = db.set_chat_attachment_status(&xfer_hex, "active", Some(position), None);
            }
            self.row = db.chat_attachment(&xfer_hex);
            if let Some(row) = &self.row {
                emit_row(app, row);
            }
            self.last_emit = Some(Instant::now());
            return true;
        }
        if position >= size {
            self.queued_all = true;
            if let Some(row) = &self.row {
                emit_progress(app, db, row, position);
            }
            return true;
        }
        let due = self
            .last_emit
            .is_none_or(|at| at.elapsed() >= PROGRESS_INTERVAL);
        if !due {
            return true;
        }
        self.last_emit = Some(Instant::now());
        let now = chrono::Utc::now().timestamp();
        if db.chat_attachment_grant(&xfer_hex, peer_hex, now).is_none() {
            return false;
        }
        if let Some(row) = &self.row {
            emit_progress(app, db, row, position);
        }
        true
    }

    /// The stream is over. `delivered` is whether the friend acknowledged
    /// every byte. Only then is the row finished — otherwise it is left for
    /// the friend's retry or its cancel to settle.
    pub(crate) fn finish(&self, db: &Database, app: &tauri::AppHandle, delivered: bool) {
        let Some(row) = &self.row else {
            return;
        };
        if !(delivered && self.queued_all) {
            return;
        }
        let _ = db.advance_chat_attachment(&row.xfer_id, "complete", Some(row.file_size), None);
        emit_by_id(app, db, &row.xfer_id);
    }
}

// --- Receiving ---------------------------------------------------------------

/// A friend offered us a file. Record it, and fetch it now if it is under the
/// user's ceiling.
pub(super) async fn on_offer(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    settings: &AppSettings,
    friend: [u8; 16],
    offer: AttachOffer,
    peer_addr: Option<SocketAddr>,
) {
    let xfer_id = offer.xfer_id;
    let xfer_hex = hex::encode(xfer_id);
    let refuse = |reply: AttachReply| attach::encode_attach_reply(&xfer_id, reply, None);

    if settings.friend_chat_disabled {
        // The chat switch doubles as "no unsolicited contact from friends",
        // exactly as it does for file offers, rather than a second control
        // that could disagree with it.
        let _ = send_ext(state, &friend, EMBER_EXT_ATTACH_REPLY, &refuse(AttachReply::NotAllowed)).await;
        return;
    }
    // A transfer id we already know is a replay or a duplicate delivery, not a
    // second offer, and must not overwrite what the first one became.
    if state.attach_inbound.contains_key(&xfer_id) || db.chat_attachment(&xfer_hex).is_some() {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    // Only a race gets here — the sender refuses to offer over a relayed
    // session — but an offer with no address behind it can never be fetched,
    // so it is settled now rather than left for an Accept that cannot work.
    if peer_addr.is_none() {
        let name = crate::security::sanitize_filename(&offer.name);
        if db
            .upsert_chat_attachment(
                &xfer_hex,
                &hex::encode(friend),
                "received",
                &name,
                offer.size,
                &hex::encode(offer.root),
                None,
                "unreachable",
                now,
                now,
            )
            .is_ok()
        {
            emit_by_id(app, db, &xfer_hex);
        }
        let _ = send_ext(
            state,
            &friend,
            EMBER_EXT_ATTACH_CANCEL,
            &attach::encode_attach_cancel(&xfer_id, AttachCancel::Unreachable),
        )
        .await;
        return;
    }
    prune_inbound(state, db, app, now);
    let pending = state
        .attach_inbound
        .values()
        .filter(|a| a.friend == friend)
        .count();
    if pending >= MAX_PENDING_PER_FRIEND {
        let _ = send_ext(state, &friend, EMBER_EXT_ATTACH_REPLY, &refuse(AttachReply::Busy)).await;
        return;
    }
    let Some(peer_pubkey) = session_pubkey(state, &friend).await else {
        return;
    };
    // Peer-supplied, so it goes through the same filename sanitizer every
    // download does before it names anything on disk or in the UI.
    let name = crate::security::sanitize_filename(&offer.name);
    if let Err(e) = db.upsert_chat_attachment(
        &xfer_hex,
        &hex::encode(friend),
        "received",
        &name,
        offer.size,
        &hex::encode(offer.root),
        None,
        "awaiting",
        now,
        now + ATTACH_OFFER_TTL_SECS,
    ) {
        warn!("Chat attachment: could not record an offer: {e}");
        return;
    }
    let size = offer.size;
    state.attach_inbound.insert(
        xfer_id,
        InboundAttach {
            friend,
            peer_pubkey,
            peer_addr,
            offer,
            name,
            received_at: now,
        },
    );

    // Announced only once it is known to be waiting on the user: the UI treats
    // `awaiting` as "offered you a file", which is wrong for one fetched
    // without asking.
    if !try_auto_accept(state, db, app, settings, friend, xfer_id, size, now).await {
        emit_by_id(app, db, &xfer_hex);
    }
}

/// Fetch a fresh offer without asking, if it is under the user's ceiling and
/// the friend's budget. False leaves it waiting for the user rather than
/// refused: they can still take it.
#[allow(clippy::too_many_arguments)]
async fn try_auto_accept(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    settings: &AppSettings,
    friend: [u8; 16],
    xfer_id: [u8; 16],
    size: u64,
    now: i64,
) -> bool {
    let xfer_hex = hex::encode(xfer_id);
    let ceiling = settings
        .chat_attachment_auto_accept_mb
        .min(crate::types::CHAT_ATTACHMENT_AUTO_ACCEPT_MAX_MB)
        .saturating_mul(1024 * 1024);
    if ceiling == 0 || size > ceiling || !fetch_slot_free(state, db, &friend) {
        return false;
    }
    // Bound the map itself: an entry per friend who ever auto-sent, dropped
    // once its window has emptied.
    state
        .attach_auto_log
        .retain(|_, log| log.back().is_some_and(|(at, _)| now - *at < AUTO_ACCEPT_WINDOW_SECS));
    let log = state.attach_auto_log.entry(friend).or_default();
    if !auto_accept_allowed(log, now, size, ceiling) {
        debug!("Chat attachment: {xfer_hex} waits for the user; this friend's auto-accept budget is spent");
        return false;
    }
    match accept_offer(state, db, app, settings, xfer_id).await {
        Ok(()) => {
            state
                .attach_auto_log
                .entry(friend)
                .or_default()
                .push_back((now, size));
            true
        }
        Err(e) => {
            debug!("Chat attachment: auto-accept of {xfer_hex} deferred: {e}");
            false
        }
    }
}

/// Whether a friend's offer of `size` bytes may still be fetched without asking.
///
/// The ceiling alone bounds one file, not a friend. Without a budget a
/// compromised friend client could send an endless run of files just under it
/// and fill the disk while nobody was looking. Past the budget an offer is not
/// refused — it waits for the user like any larger file would — so an honest
/// burst of photos costs a click, never the files.
pub(super) fn auto_accept_allowed(
    log: &mut std::collections::VecDeque<(i64, u64)>,
    now: i64,
    size: u64,
    ceiling: u64,
) -> bool {
    while log
        .front()
        .is_some_and(|(at, _)| now - *at >= AUTO_ACCEPT_WINDOW_SECS)
    {
        log.pop_front();
    }
    let spent: u64 = log.iter().map(|(_, bytes)| *bytes).sum();
    let byte_budget = AUTO_ACCEPT_MAX_BYTES.max(ceiling);
    log.len() < AUTO_ACCEPT_MAX_FILES && spent.saturating_add(size) <= byte_budget
}

/// Retire offers nobody answered in time.
fn prune_inbound(state: &mut NetworkState, db: &Database, app: &tauri::AppHandle, now: i64) {
    let lapsed: Vec<[u8; 16]> = state
        .attach_inbound
        .iter()
        .filter(|(_, a)| a.received_at + ATTACH_OFFER_TTL_SECS <= now)
        .map(|(id, _)| *id)
        .collect();
    for id in lapsed {
        state.attach_inbound.remove(&id);
        let xfer_hex = hex::encode(id);
        let _ = db.set_chat_attachment_status(&xfer_hex, "expired", None, None);
        emit_by_id(app, db, &xfer_hex);
    }
}

/// The user answered an offer.
pub(super) async fn respond(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    settings: &AppSettings,
    xfer_id: [u8; 16],
    accept: bool,
) -> Result<(), String> {
    prune_inbound(state, db, app, chrono::Utc::now().timestamp());
    if !state.attach_inbound.contains_key(&xfer_id) {
        return Err(not_found());
    }
    if accept {
        return accept_offer(state, db, app, settings, xfer_id).await;
    }
    let Some(inbound) = state.attach_inbound.remove(&xfer_id) else {
        return Err(not_found());
    };
    let reply = attach::encode_attach_reply(&xfer_id, AttachReply::Decline, None);
    // Best effort: a friend who has gone offline will see the offer lapse.
    let _ = send_ext(state, &inbound.friend, EMBER_EXT_ATTACH_REPLY, &reply).await;
    let xfer_hex = hex::encode(xfer_id);
    let _ = db.set_chat_attachment_status(&xfer_hex, "declined", None, None);
    emit_by_id(app, db, &xfer_hex);
    Ok(())
}

async fn accept_offer(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    settings: &AppSettings,
    xfer_id: [u8; 16],
) -> Result<(), String> {
    let Some((friend, size)) = state
        .attach_inbound
        .get(&xfer_id)
        .map(|inbound| (inbound.friend, inbound.offer.size))
    else {
        return Err(not_found());
    };
    if !fetch_slot_free(state, db, &friend) {
        return Err(coded(
            "peers_attach_busy",
            "Too many files are already downloading. Try again when one finishes.",
        ));
    }
    // Room for the whole file first; the offer stays answerable when there is
    // not. A volume that cannot report its space is let through, as eD2K
    // downloads do; a full disk still fails the write safely.
    let free = tokio::task::spawn_blocking({
        let root = std::path::PathBuf::from(&settings.download_folder);
        move || fs2::available_space(root).ok()
    })
    .await
    .ok()
    .flatten();
    if free.is_some_and(|free| free < size.saturating_add(ATTACH_DISK_HEADROOM)) {
        return Err(coded(
            "peers_attach_no_space",
            "Not enough free disk space for this file",
        ));
    }
    let Some(endpoint) = quic_endpoint(state) else {
        return Err(unavailable());
    };
    let Some(inbound) = state.attach_inbound.remove(&xfer_id) else {
        return Err(not_found());
    };
    let Some(dial) = inbound
        .peer_addr
        .and_then(|addr| dial_target(addr.ip(), inbound.offer.quic_port))
    else {
        let _ = send_ext(
            state,
            &inbound.friend,
            EMBER_EXT_ATTACH_CANCEL,
            &attach::encode_attach_cancel(&xfer_id, AttachCancel::Unreachable),
        )
        .await;
        let xfer_hex = hex::encode(xfer_id);
        let _ = db.set_chat_attachment_status(&xfer_hex, "unreachable", None, None);
        emit_by_id(app, db, &xfer_hex);
        return Err(relayed());
    };
    // The port the sender punches toward, chosen for how it reaches us.
    let reply = attach::encode_attach_reply(
        &xfer_id,
        AttachReply::Accept,
        quic_port_for(state, inbound.peer_addr),
    );
    if let Err(e) = send_ext(state, &inbound.friend, EMBER_EXT_ATTACH_REPLY, &reply).await {
        // Put it back: the user can try again once the friend reconnects, until
        // the offer lapses.
        state.attach_inbound.insert(xfer_id, inbound);
        return Err(e);
    }
    let cancel_tx = session_tx(state, &inbound.friend).await;
    let xfer_hex = hex::encode(xfer_id);
    let _ = db.set_chat_attachment_status(&xfer_hex, "active", Some(0), None);
    let _ = db.set_chat_attachment_expiry(
        &xfer_hex,
        chrono::Utc::now().timestamp() + ATTACH_GRANT_TTL_SECS,
    );
    let Some(row) = db.chat_attachment(&xfer_hex) else {
        return Err(not_found());
    };
    emit_row(app, &row);

    let ctx = FetchCtx {
        db: db.clone(),
        app: app.clone(),
        endpoint,
        seed: state.local_ed25519_seed,
        our_pubkey: state.local_ed25519_pubkey,
        friend: inbound.friend,
        peer_pubkey: inbound.peer_pubkey,
        dial,
        tcp_dials: friend_tcp_candidates(db, &inbound.friend, inbound.peer_addr),
        xfer_id,
        size: inbound.offer.size,
        root: inbound.offer.root,
        name: inbound.name,
        download_folder: PathBuf::from(&settings.download_folder),
        cancel_tx,
        row,
    };
    let handle = tokio::spawn(run_fetch(ctx));
    state.attach_fetches.insert(xfer_id, handle);
    Ok(())
}

struct FetchCtx {
    db: Arc<Database>,
    app: tauri::AppHandle,
    endpoint: Arc<quinn::Endpoint>,
    seed: [u8; 32],
    our_pubkey: [u8; 32],
    friend: [u8; 16],
    peer_pubkey: [u8; 32],
    dial: SocketAddr,
    /// The friend's upload listener, for when `dial` does not connect. See
    /// [`friend_tcp_candidates`].
    tcp_dials: Vec<SocketAddr>,
    xfer_id: [u8; 16],
    size: u64,
    root: [u8; 32],
    name: String,
    download_folder: PathBuf,
    /// The friend session at the time of accepting, to tell the sender if the
    /// receive has to be abandoned. A session that has since been replaced
    /// makes this a no-op, which is the right outcome — nobody is listening.
    cancel_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    /// Snapshot for progress ticks.
    row: ChatAttachmentRow,
}

/// Why a receive stopped.
enum ReceiveFailure {
    /// The bytes did not match what was offered.
    Corrupt(String),
    /// The sender refused the stream.
    Refused(AttachStreamStatus),
    /// Connected, but the stream kept dropping.
    Unreachable(String),
    /// No dial ever connected: there is no direct path to the sender.
    NoRoute(String),
    /// We could not prepare or finish the file on disk.
    Disk(String),
}

impl std::fmt::Display for ReceiveFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiveFailure::Corrupt(d) => write!(f, "content did not verify: {d}"),
            ReceiveFailure::Refused(s) => write!(f, "sender refused: {s:?}"),
            ReceiveFailure::Unreachable(d) => write!(f, "lost the sender: {d}"),
            ReceiveFailure::NoRoute(d) => write!(f, "could not reach the sender: {d}"),
            ReceiveFailure::Disk(d) => write!(f, "could not save the file: {d}"),
        }
    }
}

async fn run_fetch(ctx: FetchCtx) {
    let xfer_hex = hex::encode(ctx.xfer_id);
    match fetch_to_chat_files(&ctx).await {
        Ok(true) => info!("Chat attachment: received {xfer_hex} ({} bytes)", ctx.size),
        Ok(false) => debug!("Chat attachment: {xfer_hex} ended while it was being saved"),
        Err(failure) => {
            warn!("Chat attachment: receive of {xfer_hex} failed: {failure}");
            let (status, reason) = failure_outcome(&failure);
            // A row that already ended — the user cancelled — keeps that
            // status, and the sender was told when it did.
            let failed = ctx
                .db
                .advance_chat_attachment(&xfer_hex, status, None, None)
                .unwrap_or(false);
            if let (true, Some(tx)) = (failed, &ctx.cancel_tx) {
                let _ = tx.try_send(build_ember_ext_frame(
                    EMBER_EXT_ATTACH_CANCEL,
                    &attach::encode_attach_cancel(&ctx.xfer_id, reason),
                ));
            }
        }
    }
    emit_by_id(&ctx.app, &ctx.db, &xfer_hex);
}

/// What a failed receive leaves on our row, and what the sender is told. The
/// two causes a user can act on get their own status; the rest are `failed`.
fn failure_outcome(failure: &ReceiveFailure) -> (&'static str, AttachCancel) {
    match failure {
        ReceiveFailure::NoRoute(_) => ("unreachable", AttachCancel::Unreachable),
        ReceiveFailure::Refused(AttachStreamStatus::SourceGone) => {
            ("source_gone", AttachCancel::SourceGone)
        }
        ReceiveFailure::Corrupt(_) => ("failed", AttachCancel::Corrupt),
        _ => ("failed", AttachCancel::Stalled),
    }
}

/// Receive, verify, and move the file into `Chat Files`, marking the row
/// complete. `Ok(false)` when the row ended while the file was being moved.
async fn fetch_to_chat_files(ctx: &FetchCtx) -> Result<bool, ReceiveFailure> {
    let root = ctx.download_folder.clone();
    let allowed = vec![root.to_string_lossy().into_owned()];

    // Through the approved-root layer, like every other download: the part
    // name derives from a transfer id the sender chose, so opening it by path
    // would follow anything planted there. Truncated because a receive does not
    // resume across processes; retries inside this task resume from the handle.
    let prepared = tokio::task::spawn_blocking({
        let root = root.clone();
        let allowed = allowed.clone();
        let part_name = part_file_name(&ctx.xfer_id);
        move || -> std::io::Result<_> {
            use crate::security::filesystem as fs;
            let temp = fs::prepare_approved_subdir(&root, "Temp", &allowed)?;
            let chat = fs::prepare_approved_subdir(&root, CHAT_FILES_DIR, &allowed)?;
            let (part_path, file) = fs::open_or_create_approved(&temp.join(part_name), &allowed, true)?;
            let identity = fs::object_identity_from_file(&file)?;
            Ok((part_path, chat, identity, file))
        }
    })
    .await
    .map_err(|e| ReceiveFailure::Disk(e.to_string()))?
    .map_err(|e| ReceiveFailure::Disk(e.to_string()))?;
    let (part_path, chat_dir, identity, part) = prepared;

    let result = receive_with_retries(ctx, &part).await;
    drop(part);
    if let Err(failure) = result {
        let _ = std::fs::remove_file(&part_path);
        return Err(failure);
    }

    let name = ctx.name.clone();
    let db = ctx.db.clone();
    let xfer_hex = hex::encode(ctx.xfer_id);
    let size = ctx.size;
    // The row is settled on the blocking thread, not back in this task. A
    // cancel aborts the task but cannot stop the move, so whichever of the two
    // writes the row first decides whether the moved file stays.
    tokio::task::spawn_blocking(move || {
        let target = super::unique_download_path(&chat_dir.join(&name));
        let dest = super::ed2k::transfer::move_part_to_final_approved(
            &part_path, &target, &root, &identity,
        )
        .map_err(|e| {
            let _ = std::fs::remove_file(&part_path);
            e.to_string()
        })?;
        let dest_str = dest.to_string_lossy().into_owned();
        match db.advance_chat_attachment(&xfer_hex, "complete", Some(size), Some(&dest_str)) {
            Ok(true) => Ok(true),
            Ok(false) => {
                let _ = std::fs::remove_file(&dest);
                Ok(false)
            }
            Err(e) => {
                let _ = std::fs::remove_file(&dest);
                Err(e.to_string())
            }
        }
    })
    .await
    .map_err(|e| ReceiveFailure::Disk(e.to_string()))?
    .map_err(ReceiveFailure::Disk)
}

async fn receive_with_retries(ctx: &FetchCtx, part: &std::fs::File) -> Result<(), ReceiveFailure> {
    let capability = attach::derive_attach_capability(&ctx.seed, &ctx.peer_pubkey, &ctx.xfer_id)
        .ok_or_else(|| ReceiveFailure::Unreachable("the friend's key is not usable".into()))?;
    let (cert, key) = super::ember::quic::generate_self_signed_cert(&ctx.seed)
        .map_err(|e| ReceiveFailure::Unreachable(e.to_string()))?;

    let mut last = ReceiveFailure::Unreachable("no attempt was made".into());
    let mut connected = false;
    let mut tcp_tried = false;
    let mut status_waited = Duration::ZERO;
    for attempt in 0..FETCH_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(1u64 << attempt.min(3))).await;
        }
        let dialled = tokio::time::timeout(
            DIAL_TIMEOUT,
            super::ember::quic::connect_pinned(
                &ctx.endpoint,
                ctx.dial,
                "ember",
                // Pinned: the certificate the sender presents must hash to the
                // friend we accepted from, so nobody else can answer this dial.
                Some((&cert, &key, ctx.friend)),
            ),
        )
        .await;
        let conn = match dialled {
            Ok(Ok(conn)) => Some(conn),
            Ok(Err(e)) => {
                info!(
                    "Chat attachment: dial {}/{FETCH_ATTEMPTS} to {} failed: {e}",
                    attempt + 1,
                    ctx.dial
                );
                last = ReceiveFailure::Unreachable(e.to_string());
                None
            }
            Err(_) => {
                info!(
                    "Chat attachment: dial {}/{FETCH_ATTEMPTS} to {} timed out",
                    attempt + 1,
                    ctx.dial
                );
                last = ReceiveFailure::Unreachable("the connection timed out".into());
                None
            }
        };
        let Some(conn) = conn else {
            // QUIC listens on a UDP port of its own, which a setup forwarding
            // only the eD2K ports never opens. Try the friend's TCP listener
            // once, straight after the first miss, before spending the
            // remaining QUIC retries.
            if !connected && !tcp_tried {
                tcp_tried = true;
                if let Some(done) = receive_over_tcp(ctx, part, &capability, &mut status_waited).await
                {
                    return done;
                }
            }
            continue;
        };
        connected = true;
        let (mut send, mut recv) = match conn.open_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                last = ReceiveFailure::Unreachable(e.to_string());
                continue;
            }
        };
        let handle = part
            .try_clone()
            .map_err(|e| ReceiveFailure::Disk(e.to_string()))?;
        let mut last_emit: Option<Instant> = None;
        let status_wait = next_status_wait(status_waited);
        let fetched = attach_stream::fetch_attachment_waiting(
            &mut recv,
            &mut send,
            &ctx.xfer_id,
            &capability,
            ctx.size,
            &ctx.root,
            handle,
            |done, _| {
                if last_emit.is_none_or(|at| at.elapsed() >= PROGRESS_INTERVAL) {
                    last_emit = Some(Instant::now());
                    emit_progress(&ctx.app, &ctx.db, &ctx.row, done);
                }
            },
            status_wait,
            &mut status_waited,
        )
        .await;
        let _ = send.finish();
        let reason = match &fetched {
            Ok(outcome) if outcome.complete => attach::ATTACH_CLOSE_RECEIVED,
            _ => attach::ATTACH_CLOSE_ABANDONED,
        };
        conn.close(0u32.into(), reason);
        match fetched {
            Ok(outcome) if outcome.complete => return Ok(()),
            Ok(_) => last = ReceiveFailure::Unreachable("the stream ended early".into()),
            Err(FetchError::Corrupt(detail)) => return Err(ReceiveFailure::Corrupt(detail)),
            Err(FetchError::Refused(status)) => return Err(ReceiveFailure::Refused(status)),
            Err(FetchError::Transient(e)) => last = ReceiveFailure::Unreachable(e.to_string()),
        }
    }
    Err(match last {
        ReceiveFailure::Unreachable(detail) if !connected => ReceiveFailure::NoRoute(detail),
        other => other,
    })
}

/// Where the friend's upload listener may answer over TCP. The IP is the
/// session's; the port is the listening one the friends table records, then
/// the session's own, which is the listener's when we were the ones who
/// dialled it.
fn friend_tcp_candidates(
    db: &Database,
    friend: &[u8; 16],
    session: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    let Some(session) = session else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(Some((_, port))) = db.get_friend_address(&hex::encode(friend)) {
        out.extend(dial_target(session.ip(), port));
    }
    if let Some(addr) = dial_target(session.ip(), session.port()) {
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// The fallback when QUIC cannot connect: the friend's upload listener, over
/// the secure stream a friend session uses. `None` when no candidate connects
/// either, so the caller can go on trying QUIC; otherwise how the receive
/// ended.
async fn receive_over_tcp(
    ctx: &FetchCtx,
    part: &std::fs::File,
    capability: &[u8; 32],
    status_waited: &mut Duration,
) -> Option<Result<(), ReceiveFailure>> {
    use super::ember::attach_tcp;
    let our_hash = super::ember::crypto::node_id_from_ed25519_bytes(&ctx.our_pubkey)?;
    let mut reached: Option<SocketAddr> = None;
    let mut last = ReceiveFailure::Unreachable("no TCP attempt was made".into());
    for attempt in 0..FETCH_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(1u64 << attempt.min(3))).await;
        }
        // Every candidate until one answers; after that, only that one.
        let targets = match reached {
            Some(addr) => vec![addr],
            None => ctx.tcp_dials.clone(),
        };
        let mut parts = None;
        for addr in targets {
            match attach_tcp::dial_secure(addr, our_hash, ctx.our_pubkey, ctx.seed, ctx.friend).await {
                Ok(connected) => {
                    info!("Chat attachment: reached the sender over TCP at {addr}");
                    reached = Some(addr);
                    parts = Some(connected);
                    break;
                }
                Err(e) => info!("Chat attachment: TCP dial to {addr} failed: {e}"),
            }
        }
        let Some(mut parts) = parts else {
            reached?;
            last = ReceiveFailure::Unreachable("the TCP redial failed".into());
            continue;
        };
        let handle = match part.try_clone() {
            Ok(handle) => handle,
            Err(e) => return Some(Err(ReceiveFailure::Disk(e.to_string()))),
        };
        let mut last_emit: Option<Instant> = None;
        let fetched = attach_tcp::fetch_over_tcp(
            &mut parts,
            attach::ATTACH_STREAM_MSG_TYPE,
            &ctx.xfer_id,
            capability,
            ctx.size,
            &ctx.root,
            handle,
            |done, _| {
                if last_emit.is_none_or(|at| at.elapsed() >= PROGRESS_INTERVAL) {
                    last_emit = Some(Instant::now());
                    emit_progress(&ctx.app, &ctx.db, &ctx.row, done);
                }
            },
            next_status_wait(*status_waited),
            status_waited,
        )
        .await;
        match fetched {
            Ok(outcome) if outcome.complete => return Some(Ok(())),
            Ok(_) => last = ReceiveFailure::Unreachable("the stream ended early".into()),
            Err(FetchError::Corrupt(detail)) => return Some(Err(ReceiveFailure::Corrupt(detail))),
            Err(FetchError::Refused(status)) => return Some(Err(ReceiveFailure::Refused(status))),
            Err(FetchError::Transient(e)) => last = ReceiveFailure::Unreachable(e.to_string()),
        }
    }
    Some(Err(last))
}

// --- Either side ---------------------------------------------------------------

/// Stop whatever this node is doing for `xfer_id` and clear its part file.
fn stop_local(state: &mut NetworkState, download_folder: &str, xfer_id: &[u8; 16]) {
    state.attach_inbound.remove(xfer_id);
    if let Some(handle) = state.attach_fetches.remove(xfer_id) {
        handle.abort();
        // The aborted task never reaches its own cleanup. Removing a link by
        // name removes the link, not what it points at, so a planted symlink
        // here cannot turn this into a delete elsewhere.
        let part = PathBuf::from(download_folder)
            .join("Temp")
            .join(part_file_name(xfer_id));
        let _ = std::fs::remove_file(part);
    }
}

/// The user stopped a transfer, in either direction.
pub(super) async fn cancel(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    settings: &AppSettings,
    xfer_id: [u8; 16],
) -> Result<(), String> {
    let xfer_hex = hex::encode(xfer_id);
    let Some(row) = db.chat_attachment(&xfer_hex) else {
        return Err(not_found());
    };
    // Written before anything is stopped, and only over a live row: a receive
    // saving its file right now either finishes first and keeps it, or finds
    // the row cancelled and removes what it moved. A stream we are serving
    // sees the grant gone and stops.
    let cancelled = db
        .advance_chat_attachment(&xfer_hex, "cancelled", None, None)
        .unwrap_or(false);
    // Whatever the row says: a receive still running under a row that ended
    // without it has to be stoppable too.
    stop_local(state, &settings.download_folder, &xfer_id);
    let mut friend = [0u8; 16];
    if cancelled && hex::decode_to_slice(&row.friend_hash, &mut friend).is_ok() {
        // Best effort: an offline friend finds out when their side lapses.
        let _ = send_ext(
            state,
            &friend,
            EMBER_EXT_ATTACH_CANCEL,
            &attach::encode_attach_cancel(&xfer_id, AttachCancel::User),
        )
        .await;
    }
    emit_by_id(app, db, &xfer_hex);
    Ok(())
}

/// The friend stopped a transfer.
pub(super) fn on_cancel(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    settings: &AppSettings,
    friend: [u8; 16],
    xfer_id: [u8; 16],
    reason: AttachCancel,
) {
    let xfer_hex = hex::encode(xfer_id);
    let Some(row) = db.chat_attachment(&xfer_hex) else {
        return;
    };
    // Only the friend on the other end of this transfer may stop it.
    if row.friend_hash != hex::encode(friend) {
        return;
    }
    let status = match reason {
        AttachCancel::User => "cancelled",
        AttachCancel::Unreachable => "unreachable",
        AttachCancel::SourceGone => "source_gone",
        AttachCancel::Stalled | AttachCancel::Corrupt => "failed",
    };
    let moved = db
        .advance_chat_attachment(&xfer_hex, status, None, None)
        .unwrap_or(false);
    stop_local(state, &settings.download_folder, &xfer_id);
    if moved {
        emit_by_id(app, db, &xfer_hex);
    }
}

/// Settle what a restart stranded.
///
/// An `awaiting` offer's details lived only in memory, so it can no longer be
/// accepted; an `active` receive was cut off mid-file and does not resume
/// across processes. Both are marked and their part files cleared, so the
/// transcript says what happened instead of showing a transfer that will never
/// move. Unanswered offers of our own keep their grant until it lapses — the
/// friend may still answer after we come back — and a send that was cut off
/// goes back to `accepted`, since the friend's receive can resume against the
/// same grant if it dials again.
pub(super) fn sweep_interrupted(db: &Database, download_folder: &str) {
    let now = chrono::Utc::now().timestamp();
    let _ = db.expire_chat_attachments(now);
    let _ = db.requeue_interrupted_outbound_chat_attachments();
    let Ok(stranded) = db.interrupted_inbound_chat_attachments() else {
        return;
    };
    for (xfer_hex, status) in stranded {
        let next = if status == "awaiting" { "expired" } else { "failed" };
        let _ = db.set_chat_attachment_status(&xfer_hex, next, None, None);
        let mut id = [0u8; 16];
        if hex::decode_to_slice(&xfer_hex, &mut id).is_ok() {
            let part = PathBuf::from(download_folder)
                .join("Temp")
                .join(part_file_name(&id));
            let _ = std::fs::remove_file(part);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_addresses_that_can_be_a_peer_are_dialled() {
        let ok = dial_target("203.0.113.7".parse().unwrap(), 41330);
        assert_eq!(ok, Some("203.0.113.7:41330".parse().unwrap()));

        // Loopback stays dialable: two instances on one machine is how the
        // multi-node harness runs, and the session really is from there.
        assert!(dial_target("127.0.0.1".parse().unwrap(), 41330).is_some());

        assert!(dial_target("0.0.0.0".parse().unwrap(), 41330).is_none());
        assert!(dial_target("224.0.0.1".parse().unwrap(), 41330).is_none());
        assert!(dial_target("255.255.255.255".parse().unwrap(), 41330).is_none());
        assert!(dial_target("203.0.113.7".parse().unwrap(), 0).is_none());
    }

    /// The QUIC endpoint is bound on IPv4, so a session that arrived on a
    /// dual-stack socket has to be dialled on its IPv4 form, and a real IPv6
    /// address cannot be dialled at all.
    #[test]
    fn a_mapped_address_is_folded_back_to_ipv4() {
        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        assert_eq!(
            dial_target(mapped, 41330),
            Some("203.0.113.7:41330".parse().unwrap())
        );
        assert!(dial_target("2001:db8::1".parse().unwrap(), 41330).is_none());
    }

    /// A NAT that re-maps ports gives the endpoint a public port different
    /// from the one it listens on. A friend across the internet needs the
    /// public one; a friend on the same network can only reach the local one.
    #[test]
    fn a_friend_on_the_same_network_is_given_the_local_port() {
        let (local, public) = (Some(48545), Some(63786));
        let port = |peer: &str| choose_quic_port(local, public, Some(peer.parse().unwrap()));
        for lan in [
            "192.168.1.20:48544",
            "10.0.0.5:48544",
            "172.20.1.9:48544",
            "169.254.3.4:48544",
            "127.0.0.1:48544",
            "100.101.102.103:48544",
            "[::ffff:192.168.1.20]:48544",
            "[fd12:3456::1]:48544",
            "[fe80::1]:48544",
        ] {
            assert_eq!(port(lan), Some(48545), "{lan}");
        }
        assert_eq!(port("203.0.113.7:48544"), Some(63786));
        assert_eq!(choose_quic_port(local, public, None), Some(63786), "no direct address");
        assert_eq!(
            choose_quic_port(None, public, Some("192.168.1.20:1".parse().unwrap())),
            Some(63786),
            "no local port known yet"
        );
    }

    #[test]
    fn every_status_that_ends_a_transfer_is_terminal() {
        for status in [
            "complete",
            "declined",
            "too_large",
            "busy",
            "not_allowed",
            "cancelled",
            "unreachable",
            "source_gone",
            "failed",
            "expired",
        ] {
            assert!(is_terminal(status), "{status}");
        }
        for status in ["offered", "awaiting", "accepted", "active"] {
            assert!(!is_terminal(status), "{status}");
        }
    }

    /// A receive that never connected says so on both ends; one that connected
    /// and then lost the sender is an ordinary failure, because the direct path
    /// did exist.
    /// One friend may not hold every receive slot, however many they offer.
    #[test]
    fn one_friend_cannot_take_every_attach_receive_slot() {
        assert!(fetch_slots_allow(0, 0));
        assert!(fetch_slots_allow(MAX_ACTIVE_FETCHES_PER_FRIEND, MAX_ACTIVE_FETCHES_PER_FRIEND - 1));
        assert!(!fetch_slots_allow(MAX_ACTIVE_FETCHES_PER_FRIEND, MAX_ACTIVE_FETCHES_PER_FRIEND));
        assert!(!fetch_slots_allow(MAX_ACTIVE_FETCHES, 0), "the total still binds");
        const _: () = assert!(MAX_ACTIVE_FETCHES_PER_FRIEND < MAX_ACTIVE_FETCHES);
    }

    /// A stream that dropped before the sender answered leaves the next one
    /// the rest of the long wait, not the retry floor: a large file on a slow
    /// sender is still hashing. One that waited it out leaves only the floor.
    #[test]
    fn only_time_spent_waiting_for_the_sender_uses_up_the_status_wait() {
        use attach_stream::{ATTACH_RETRY_STATUS_TIMEOUT, ATTACH_STATUS_TIMEOUT};
        assert_eq!(next_status_wait(Duration::ZERO), ATTACH_STATUS_TIMEOUT);
        assert_eq!(
            next_status_wait(Duration::from_secs(5)),
            ATTACH_STATUS_TIMEOUT - Duration::from_secs(5)
        );
        assert_eq!(next_status_wait(ATTACH_STATUS_TIMEOUT), ATTACH_RETRY_STATUS_TIMEOUT);
        assert_eq!(
            next_status_wait(ATTACH_STATUS_TIMEOUT * 2),
            ATTACH_RETRY_STATUS_TIMEOUT
        );
    }

    #[test]
    fn a_receive_that_never_connected_is_unreachable_not_failed() {
        assert_eq!(
            failure_outcome(&ReceiveFailure::NoRoute("timed out".into())),
            ("unreachable", AttachCancel::Unreachable)
        );
        assert_eq!(
            failure_outcome(&ReceiveFailure::Unreachable("stream ended early".into())),
            ("failed", AttachCancel::Stalled)
        );
        assert_eq!(
            failure_outcome(&ReceiveFailure::Refused(AttachStreamStatus::SourceGone)),
            ("source_gone", AttachCancel::SourceGone)
        );
        assert_eq!(
            failure_outcome(&ReceiveFailure::Corrupt("chunk 3".into())),
            ("failed", AttachCancel::Corrupt)
        );
    }

    /// A cancelled transfer's row must not be walked back by a stream that was
    /// already running when the user pressed cancel.
    #[test]
    fn a_running_stream_cannot_revive_a_finished_row() {
        for status in ["offered", "accepted", "active"] {
            assert!(ServeProgress::writable(status), "{status}");
        }
        for status in ["cancelled", "failed", "expired", "declined", "complete"] {
            assert!(!ServeProgress::writable(status), "{status}");
        }
    }

    /// An accept moves a fresh offer onto the grant's lifetime once, and a
    /// late or repeated one cannot move it again.
    #[test]
    fn an_accept_extends_a_grant_once_and_never_revives_one() {
        let created = 1_000;
        let offer_expiry = created + ATTACH_OFFER_TTL_SECS;
        let extends = |expires_at, now| accept_extends_grant(created, expires_at, now);
        assert_eq!(extends(offer_expiry, created + 10), Some(true));
        assert_eq!(extends(offer_expiry, offer_expiry), None);
        assert_eq!(extends(offer_expiry, offer_expiry + 60), None);

        let granted = created + 10 + ATTACH_GRANT_TTL_SECS;
        assert_eq!(extends(granted, created + 20), Some(false));
        assert_eq!(extends(granted, granted), None);
    }

    const MB: u64 = 1024 * 1024;

    /// The ceiling bounds one file; this bounds a friend. A run of files just
    /// under the ceiling stops being fetched silently at the file count.
    #[test]
    fn a_run_of_small_files_stops_auto_accepting_at_the_file_budget() {
        let mut log = std::collections::VecDeque::new();
        let now = 10_000;
        for _ in 0..AUTO_ACCEPT_MAX_FILES {
            assert!(auto_accept_allowed(&mut log, now, MB, 25 * MB));
            log.push_back((now, MB));
        }
        assert!(!auto_accept_allowed(&mut log, now, MB, 25 * MB));
    }

    #[test]
    fn the_byte_budget_binds_before_the_file_count_for_large_files() {
        let mut log = std::collections::VecDeque::new();
        let now = 10_000;
        // Two files at a 500 MB ceiling fit a 1 GiB window; the third does not.
        for _ in 0..2 {
            assert!(auto_accept_allowed(&mut log, now, 500 * MB, 500 * MB));
            log.push_back((now, 500 * MB));
        }
        assert!(!auto_accept_allowed(&mut log, now, 500 * MB, 500 * MB));
    }

    /// Raising the ceiling past the byte budget must still let one file at that
    /// ceiling through, or the setting would silently do nothing.
    #[test]
    fn one_file_at_a_high_ceiling_is_still_allowed() {
        let mut log = std::collections::VecDeque::new();
        assert!(auto_accept_allowed(&mut log, 10_000, 2000 * MB, 2000 * MB));
    }

    #[test]
    fn the_budget_refills_once_the_window_passes() {
        let mut log = std::collections::VecDeque::new();
        let then = 10_000;
        for _ in 0..AUTO_ACCEPT_MAX_FILES {
            log.push_back((then, MB));
        }
        assert!(!auto_accept_allowed(&mut log, then + 60, MB, 25 * MB));
        assert!(auto_accept_allowed(
            &mut log,
            then + AUTO_ACCEPT_WINDOW_SECS,
            MB,
            25 * MB
        ));
        assert!(log.is_empty(), "entries past the window are dropped");
    }

    fn row(status: &str, direction: &str, dest: Option<&str>) -> ChatAttachmentRow {
        ChatAttachmentRow {
            xfer_id: "ab".repeat(16),
            friend_hash: "cd".repeat(16),
            direction: direction.into(),
            file_name: "f.bin".into(),
            file_size: 100,
            dest_path: dest.map(Into::into),
            status: status.into(),
            transferred: 40,
            created_at: 1,
        }
    }

    #[test]
    fn only_a_finished_received_file_can_be_opened() {
        assert!(ChatAttachmentInfo::from_row(&row("complete", "received", Some("x"))).has_file);
        assert!(!ChatAttachmentInfo::from_row(&row("complete", "sent", Some("x"))).has_file);
        assert!(!ChatAttachmentInfo::from_row(&row("active", "received", Some("x"))).has_file);
        assert!(!ChatAttachmentInfo::from_row(&row("complete", "received", None)).has_file);
    }

    #[test]
    fn a_complete_row_reports_the_whole_file() {
        assert_eq!(
            ChatAttachmentInfo::from_row(&row("complete", "received", Some("x"))).transferred,
            100
        );
        assert_eq!(
            ChatAttachmentInfo::from_row(&row("active", "received", None)).transferred,
            40
        );
    }
}
