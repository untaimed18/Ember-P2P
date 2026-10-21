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
//! | `expired`     | both     | nobody answered in time, a restart stranded it, or the session it waited on ended |

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::Emitter;
use tracing::{debug, info, warn};

use super::ed2k::messages::{
    build_ember_ext_frame, EMBER_EXT_ATTACH_CANCEL, EMBER_EXT_ATTACH_OFFER, EMBER_EXT_ATTACH_REPLY,
    EMBER_EXT_ATTACH_WAITS,
};
use super::ember::attach::{
    self, AttachCancel, AttachOffer, AttachReply, AttachStreamStatus, ATTACH_GRANT_TTL_SECS,
    ATTACH_OFFER_TTL_SECS,
};
use super::ed2k::secure_stream::SecureStreamParts;
use super::ember::attach_stream::{self, FetchError, HeldSource, SourceStamp};
use super::ember::attach_tcp;
use super::NetworkState;
use crate::commands::errors::{coded, coded_ctx};
use crate::storage::database::{ChatAttachmentRow, Database, OfferHold};
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

/// New offers one friend may make per [`NEW_OFFER_WINDOW_SECS`]. The pending
/// cap alone does not bound them: a sender that cancels its own waiting offer
/// frees the slot at once, and each offer leaves a row and a notification.
/// Generous enough for a batch of photos.
const MAX_NEW_OFFERS_PER_WINDOW: u32 = 40;
const NEW_OFFER_WINDOW_SECS: i64 = 600;

/// Per friend: the start of its current window and the offers in it. Only
/// friends reach `on_offer`, so this holds at most one entry per friend.
static NEW_OFFER_RATE: std::sync::LazyLock<
    parking_lot::Mutex<std::collections::HashMap<[u8; 16], (i64, u32)>>,
> = std::sync::LazyLock::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

fn admit_new_offer(friend: &[u8; 16], now: i64) -> bool {
    let mut rate = NEW_OFFER_RATE.lock();
    let (window_start, count) = rate.entry(*friend).or_insert((now, 0));
    if now - *window_start >= NEW_OFFER_WINDOW_SECS {
        *window_start = now;
        *count = 0;
    }
    if *count >= MAX_NEW_OFFERS_PER_WINDOW {
        return false;
    }
    *count += 1;
    true
}

/// How long a file sent to a friend we cannot reach stays queued for them
/// before it is given up as undelivered.
const ATTACH_QUEUE_TTL_SECS: i64 = 7 * 24 * 60 * 60;

/// Files one friend may have queued at once. The queue holds a readable path
/// per file until it goes, so it is kept to what someone would plausibly
/// line up for a friend who is away.
const MAX_QUEUED_PER_FRIEND: usize = 20;

/// Queued files offered to a friend at a time once they are back. The rest
/// wait for answers: the friend's side refuses more than
/// [`MAX_PENDING_PER_FRIEND`] unanswered offers as busy.
const MAX_QUEUED_OFFERS_OUTSTANDING: usize = 4;

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
    /// The name is a program, shortcut or script, or one dressed up as a
    /// document (`report.pdf.exe`); see `security::is_dangerous_extension`.
    pub risky: bool,
    /// Bumped each time the transfer is tried again, so the UI can tell this
    /// attempt's updates from late ones belonging to the attempt that ended.
    pub attempt: u32,
    /// Whether "Try again" can do anything for this row on this side.
    pub retryable: bool,
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
            risky: crate::security::is_dangerous_extension(&row.file_name),
            attempt: row.attempt,
            retryable: retryable(&row.direction, &row.status),
        }
    }
}

/// Ended sends our user may offer again under the same transfer id.
const RETRYABLE_SENT: &[&str] = &["failed", "unreachable", "busy", "expired", "undelivered"];
/// Ended receives our user may ask the sender to offer again. Only ones that
/// broke after being accepted: the sender honours nothing else (see
/// [`FRIEND_RETRYABLE_SENT`]), and anything else was refused or lapsed.
const RETRYABLE_RECEIVED: &[&str] = &["failed", "unreachable"];
/// Sends a friend may ask us to offer again: ones that broke, never ones that
/// lapsed or were refused, so a friend cannot revive a grant the user let go.
const FRIEND_RETRYABLE_SENT: &[&str] = &["failed", "unreachable"];
/// Received rows a re-offer of the same file reopens.
const REOFFER_REOPENS: &[&str] = &["failed", "unreachable", "expired"];
/// How long a "Try again" press on a received card stands as acceptance of
/// the re-offer it asked for. After that the re-offer is asked about afresh.
const RETRY_ASK_WINDOW_SECS: i64 = 120;

/// How long an offer the sender has said it holds stays answerable here, from
/// when the offer arrived. Only while the sender's word stands: a session with
/// them ending, or their asking for our notes again, puts it back on an
/// offer's lifetime from then until the sender says so again (see
/// [`InboundHold`]).
const HELD_OFFER_WAIT_SECS: i64 = ATTACH_GRANT_TTL_SECS;

/// How long a sender holds an offer the friend said it is keeping, from the
/// first time it heard so: the receiver's wait and an offer's lifetime more,
/// so an accept sent at the receiver's last moment still finds the grant. A
/// hold taken up again after a session ended runs to the same end, never
/// past it.
const HELD_OFFER_GRANT_SECS: i64 = HELD_OFFER_WAIT_SECS + ATTACH_OFFER_TTL_SECS;

/// Half-minute ticks on which a note or an empty `EMBER_EXT_ATTACH_WAITS` the
/// session had no room for is sent again: two minutes, well inside the five an
/// offer named again waits for the sender's word.
const OWED_HOLD_TRIES: u8 = 4;

fn retryable(direction: &str, status: &str) -> bool {
    match direction {
        "sent" => RETRYABLE_SENT.contains(&status),
        "received" => RETRYABLE_RECEIVED.contains(&status),
        _ => false,
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

/// A row the periodic sweep just expired.
pub(crate) fn emit_expired(app: &tauri::AppHandle, db: &Database, xfer_hex: &str) {
    emit_by_id(app, db, xfer_hex);
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
            | "undelivered"
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
    /// A re-offer our own "Try again" asked for.
    requested: bool,
    /// Where it stands with the sender about waiting for the user.
    hold: InboundHold,
    /// Half-minute ticks left to send again a note naming it that a session
    /// holding offers had no room for (see [`retry_owed_holds`]).
    notes_owed: u8,
}

/// Where an offer waiting on our user stands with its sender. Only the
/// sender's echo of our note moves it to the day-long wait, so the two ends
/// never disagree in the direction that matters: we never wait longer than
/// the sender has said it will hold the grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InboundHold {
    /// Never named to the sender: an offer's lifetime from its arrival.
    Unnamed,
    /// Named (see [`name_held_offer`]), and not confirmed since: an offer's
    /// lifetime from `since`, which is the arrival for a first note and the
    /// moment the sender's word lapsed for one named again.
    Named { since: i64 },
    /// The sender echoed the note: it holds the grant.
    Held,
}

impl InboundAttach {
    fn lapses_at(&self) -> i64 {
        inbound_lapses_at(self.received_at, self.hold)
    }
}

/// When an offer that arrived at `received_at` stops being answerable here.
fn inbound_lapses_at(received_at: i64, hold: InboundHold) -> i64 {
    let held_until = received_at + HELD_OFFER_WAIT_SECS;
    match hold {
        InboundHold::Unnamed => received_at + ATTACH_OFFER_TTL_SECS,
        InboundHold::Named { since } => (since + ATTACH_OFFER_TTL_SECS).min(held_until),
        InboundHold::Held => held_until,
    }
}

/// Our disappearing timer for a file we offer `friend`, recorded on our own
/// card. [`send_offer_frames`] carries it to theirs.
fn record_offer_ttl(db: &Arc<Database>, settings: &AppSettings, friend: [u8; 16], xfer_id: [u8; 16]) {
    let ttl = settings.chat_disappear_secs_for(&friend);
    if ttl == 0 {
        return;
    }
    let _ = db.set_chat_attachment_ttl(&hex::encode(friend), &hex::encode(xfer_id), ttl);
}

/// Send an offer with our disappearing timer for it right behind, both or
/// neither: an offer whose timer did not fit would leave the friend's card
/// in place for good while ours goes.
async fn send_offer_frames(
    state: &NetworkState,
    settings: &AppSettings,
    friend: &[u8; 16],
    xfer_id: [u8; 16],
    body: &[u8],
) -> Result<(), String> {
    let sessions = state.ember_sessions.read().await;
    let Some(session) = sessions
        .get(friend)
        .filter(|h| h.is_fresh() && h.is_secure_v2())
    else {
        return Err(friend_offline());
    };
    let mut frames = vec![build_ember_ext_frame(EMBER_EXT_ATTACH_OFFER, body)];
    let ttl = settings.chat_disappear_secs_for(friend);
    if ttl > 0 {
        let timer = super::chat::chat_expire_frame(
            &state.local_ed25519_seed,
            &session.peer_ember_pubkey(),
            crate::network::ember::crypto::ChatExpireTarget::Attachment(xfer_id),
            ttl,
        )
        .ok_or_else(|| {
            coded_ctx(
                "peers_attach_failed",
                "Could not send that file",
                "its disappearing timer could not be sealed",
            )
        })?;
        frames.push(timer);
    }
    super::chat::try_send_frames_together(&session.tx, frames).map_err(|_| friend_offline())
}

fn friend_offline() -> String {
    coded(
        "peers_attach_offline",
        "Your friend is offline. Files can only be sent while you are both connected.",
    )
}

/// The timers for a file `friend` just offered us: ours, and theirs if it
/// arrived ahead of the offer. Whichever is shorter applies.
fn note_received_ttl(
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
    friend: [u8; 16],
    xfer_id: [u8; 16],
) {
    let friend_hex = hex::encode(friend);
    let xfer_hex = hex::encode(xfer_id);
    let _ = db.set_chat_attachment_ttl(&friend_hex, &xfer_hex, settings.chat_disappear_secs_for(&friend));
    let held = super::chat::take_held_chat_expire(
        state,
        friend,
        crate::network::ember::crypto::ChatExpireTarget::Attachment(xfer_id),
    );
    if let Some(ttl) = held {
        let _ = db.set_received_chat_attachment_ttl(&friend_hex, &xfer_hex, ttl);
    }
}

async fn send_ext(
    state: &NetworkState,
    friend: &[u8; 16],
    sub_type: u8,
    body: &[u8],
) -> Result<(), String> {
    send_ext_over(&*state.ember_sessions.read().await, friend, sub_type, body)
}

/// [`send_ext`] with the session map already read.
fn send_ext_over(
    sessions: &std::collections::HashMap<[u8; 16], super::ed2k::upload::EmberSessionHandle>,
    friend: &[u8; 16],
    sub_type: u8,
    body: &[u8],
) -> Result<(), String> {
    let Some(session) = sessions
        .get(friend)
        .filter(|h| h.is_fresh() && h.is_secure_v2())
    else {
        return Err(friend_offline());
    };
    session
        .tx
        .try_send(build_ember_ext_frame(sub_type, body))
        .map_err(|_| friend_offline())
}

fn relayed() -> String {
    coded(
        "peers_attach_relayed",
        "You and your friend are only connected through a relay, and files need a direct connection. Try again later.",
    )
}

/// Whether a file can be offered to a friend right now.
pub(super) enum OfferPath {
    /// Yes, naming this QUIC port.
    Now(u16),
    /// Not yet, for this reason; it can wait in the queue until they can be
    /// reached directly.
    Later(String),
}

/// Everything that has to hold before a file can be offered, and our public
/// QUIC port when it does. Asked once before the picker opens, so the user is
/// not made to choose and hash a file that cannot go anywhere, and again with
/// the offer itself, since the session can change in between.
///
/// An error is something waiting cannot fix (chat with them is off); a friend
/// we cannot reach directly yet is [`OfferPath::Later`].
///
/// A relayed session counts as not yet rather than being tried. The
/// recipient dials the address the session came from, and a relay leaves
/// none — or only the one the session already failed to reach directly — so
/// the offer would sit through every retry and end as a failure nobody could
/// explain.
pub(super) async fn offer_path(
    state: &NetworkState,
    settings: &AppSettings,
    friend: &[u8; 16],
) -> Result<OfferPath, String> {
    if !settings.chat_allowed_with(friend) {
        return Err(chat_off_error(settings));
    }
    if quic_endpoint(state).is_none() {
        return Ok(OfferPath::Later(unavailable()));
    }
    let sessions = state.ember_sessions.read().await;
    let Some(session) = sessions
        .get(friend)
        .filter(|h| h.is_fresh() && h.is_secure_v2())
    else {
        return Ok(OfferPath::Later(coded(
            "peers_attach_offline",
            "Your friend is offline. Files can only be sent while you are both connected.",
        )));
    };
    if session.is_relayed() {
        return Ok(OfferPath::Later(relayed()));
    }
    Ok(match quic_port_for(state, session.peer_addr()) {
        Some(port) => OfferPath::Now(port),
        None => OfferPath::Later(unavailable()),
    })
}

/// [`offer_path`] for the paths that need to offer now and have no queue to
/// fall back on.
pub(super) async fn offer_preflight(
    state: &NetworkState,
    settings: &AppSettings,
    friend: &[u8; 16],
) -> Result<u16, String> {
    match offer_path(state, settings, friend).await? {
        OfferPath::Now(port) => Ok(port),
        OfferPath::Later(why) => Err(why),
    }
}

/// Why a file cannot go to a friend chat with whom is off: the global switch,
/// or this friend's own setting overriding it.
pub(crate) fn chat_off_error(settings: &AppSettings) -> String {
    if settings.friend_chat_disabled {
        coded(
            "peers_attach_disabled",
            "Chatting with friends is turned off in Settings",
        )
    } else {
        coded(
            "peers_attach_disabled_friend",
            "Chatting with this friend is turned off in your settings for them",
        )
    }
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

pub(super) fn running_fetches(state: &mut NetworkState) -> usize {
    state.attach_fetches.retain(|_, (_, handle)| !handle.is_finished());
    state.attach_fetches.len()
}

/// Whether another receive may start from `friend`.
fn fetch_slot_free(state: &mut NetworkState, friend: &[u8; 16]) -> bool {
    let total = running_fetches(state);
    let theirs = state
        .attach_fetches
        .values()
        .filter(|(from, _)| from == friend)
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

fn source_gone() -> String {
    coded(
        "peers_attach_source_gone",
        "Your friend's file changed or was moved, so it can no longer be sent",
    )
}

/// Why an offer with no answerable entry here cannot be answered, by what its
/// row became. Said without dialing: a file the sender reported changed is
/// already `source_gone` (see [`check_held_sources`]).
fn unanswerable(status: Option<&str>) -> String {
    match status {
        Some("source_gone") => source_gone(),
        _ => not_found(),
    }
}

// --- Sending -----------------------------------------------------------------

/// Record the grant for a file we are offering, then send the offer — or, if
/// the friend cannot be reached directly right now, queue it for when they
/// can (see [`send_queued`]).
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
    let path_now = offer_path(state, settings, &friend).await?;
    let offer = AttachOffer {
        xfer_id,
        size,
        root,
        quic_port: match path_now {
            OfferPath::Now(port) => port,
            OfferPath::Later(_) => 0,
        },
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
    if let OfferPath::Later(why) = path_now {
        let queued = queue_offer(db, app, friend, &xfer_hex, &name, size, root, &path_str, now, &why)?;
        // On our card now; it goes to the friend with the offer, when it can.
        record_offer_ttl(db, settings, friend, xfer_id);
        return Ok(queued);
    }
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

    if let Err(e) = send_offer_frames(state, settings, &friend, xfer_id, &body).await {
        // The session dropped between the check above and the send. Retire the
        // grant rather than leave a readable path nobody was told about.
        let _ = db.set_chat_attachment_status(&xfer_hex, "failed", None, None);
        emit_by_id(app, db, &xfer_hex);
        return Err(e);
    }
    record_offer_ttl(db, settings, friend, xfer_id);
    let row = db.chat_attachment(&xfer_hex).ok_or_else(not_found)?;
    emit_row(app, &row);
    info!(
        "Chat attachment: offered {xfer_hex} ({size} bytes) to {}",
        crate::security::short_hash(&friend),
    );
    Ok(ChatAttachmentInfo::from_row(&row))
}

fn queue_full() -> String {
    coded(
        "peers_attach_queue_full",
        "Too many files are already waiting for this friend to come online",
    )
}

/// Record a file for a friend we cannot reach directly yet. Not a grant:
/// `queued` is not on [`Database::chat_attachment_grant`]'s list, so nothing
/// can read the path until [`send_queued`] turns it into a real offer.
#[allow(clippy::too_many_arguments)]
fn queue_offer(
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    friend: [u8; 16],
    xfer_hex: &str,
    name: &str,
    size: u64,
    root: [u8; 32],
    path: &str,
    now: i64,
    why: &str,
) -> Result<ChatAttachmentInfo, String> {
    let friend_hex = hex::encode(friend);
    let queued = db
        .count_sent_chat_attachments(&friend_hex, "queued", now)
        .map_err(|e| coded_ctx("peers_attach_failed", "Could not send that file", e))?;
    if queued >= MAX_QUEUED_PER_FRIEND {
        return Err(queue_full());
    }
    db.upsert_chat_attachment(
        xfer_hex,
        &friend_hex,
        "sent",
        name,
        size,
        &hex::encode(root),
        Some(path),
        "queued",
        now,
        now + ATTACH_QUEUE_TTL_SECS,
    )
    .map_err(|e| coded_ctx("peers_attach_failed", "Could not send that file", e))?;
    let row = db.chat_attachment(xfer_hex).ok_or_else(not_found)?;
    emit_row(app, &row);
    info!(
        "Chat attachment: queued {xfer_hex} ({size} bytes) for {} until they can be reached ({why})",
        crate::security::short_hash(&friend),
    );
    Ok(ChatAttachmentInfo::from_row(&row))
}

/// Offer what is queued for `friend`, oldest first, if they can be reached
/// directly now. A few at a time: the rest go as earlier ones are answered,
/// since this runs again on every answer.
///
/// Run when a session with them comes up, on each answer to an offer, and
/// periodically, so a session that only later becomes direct is noticed too.
pub(super) async fn send_queued(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    settings: &AppSettings,
    friend: [u8; 16],
) {
    let friend_hex = hex::encode(friend);
    let now = chrono::Utc::now().timestamp();
    let outstanding = db
        .count_sent_chat_attachments(&friend_hex, "offered", now)
        .unwrap_or(usize::MAX);
    let room = MAX_QUEUED_OFFERS_OUTSTANDING.saturating_sub(outstanding);
    if room == 0 {
        return;
    }
    let Ok(queued) = db.queued_chat_attachments(&friend_hex, room) else {
        return;
    };
    if queued.is_empty() || !matches!(offer_path(state, settings, &friend).await, Ok(OfferPath::Now(_))) {
        return;
    }
    for xfer_hex in queued {
        let Some(row) = db.chat_attachment(&xfer_hex) else {
            continue;
        };
        let queue_expiry = db.chat_attachment_expiry(&xfer_hex);
        let body = match offer_again_body(state, db, settings, &friend, &xfer_hex, &row).await {
            Ok(body) => body,
            Err(OfferAgainError::SourceGone(_)) => {
                if db
                    .reopen_chat_attachment(&xfer_hex, &["queued"], "source_gone", None)
                    .unwrap_or(false)
                {
                    emit_by_id(app, db, &xfer_hex);
                }
                continue;
            }
            // The session changed under us: what is left waits for the next try.
            Err(OfferAgainError::Other(_)) => return,
        };
        let offered = db
            .reopen_chat_attachment(&xfer_hex, &["queued"], "offered", Some(now + ATTACH_OFFER_TTL_SECS))
            .unwrap_or(false);
        if !offered {
            continue;
        }
        let mut xfer_id = [0u8; 16];
        if hex::decode_to_slice(&xfer_hex, &mut xfer_id).is_err()
            || send_offer_frames(state, settings, &friend, xfer_id, &body).await.is_err()
        {
            // Back in the queue, with the time it had left.
            let _ = db.set_chat_attachment_status(&xfer_hex, "queued", None, None);
            if let Some(expiry) = queue_expiry {
                let _ = db.set_chat_attachment_expiry(&xfer_hex, expiry);
            }
            emit_by_id(app, db, &xfer_hex);
            return;
        }
        record_offer_ttl(db, settings, friend, xfer_id);
        emit_by_id(app, db, &xfer_hex);
        info!(
            "Chat attachment: offered queued {xfer_hex} ({} bytes) to {}",
            row.file_size,
            crate::security::short_hash(&friend),
        );
    }
}

enum OfferAgainError {
    /// The file is no longer where it was sent from.
    SourceGone(String),
    Other(String),
}

/// The offer we made for `row`, as it was, with our QUIC port as it is now.
async fn offer_again_body(
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
    friend: &[u8; 16],
    xfer_hex: &str,
    row: &ChatAttachmentRow,
) -> Result<Vec<u8>, OfferAgainError> {
    let mut xfer_id = [0u8; 16];
    hex::decode_to_slice(xfer_hex, &mut xfer_id).map_err(|_| OfferAgainError::Other(not_found()))?;
    let (path, size, root_hex) = db
        .chat_attachment_source(xfer_hex)
        .ok_or_else(|| OfferAgainError::Other(not_found()))?;
    let mut root = [0u8; 32];
    hex::decode_to_slice(&root_hex, &mut root).map_err(|_| OfferAgainError::Other(not_found()))?;
    let quic_port = offer_preflight(state, settings, friend)
        .await
        .map_err(OfferAgainError::Other)?;
    // Only that it is still there: whether it is still the same file is what
    // the root decides when the friend reads it.
    let present = tokio::task::spawn_blocking(move || {
        std::fs::metadata(&path).is_ok_and(|meta| meta.is_file() && meta.len() == size)
    })
    .await
    .unwrap_or(false);
    if !present {
        return Err(OfferAgainError::SourceGone(coded_ctx(
            "peers_attach_failed",
            "Could not send that file",
            "it is no longer where it was sent from",
        )));
    }
    let offer = AttachOffer {
        xfer_id,
        size,
        root,
        quic_port,
        name: row.file_name.clone(),
    };
    attach::encode_attach_offer(&offer).ok_or_else(|| {
        OfferAgainError::Other(coded_ctx(
            "peers_attach_failed",
            "Could not send that file",
            "the file name or size cannot be offered",
        ))
    })
}

/// Offer a file we sent before again, under the same transfer id, so the
/// conversation keeps one card for it. The row goes back to `status` (with
/// `expires_at` when given) only from one of `from`, and the friend gets the
/// offer it had, with our QUIC port as it is now. One the friend asked for
/// cannot be held (see [`Database::reopen_chat_attachment_for_friend`]).
#[allow(clippy::too_many_arguments)]
async fn reoffer(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    settings: &AppSettings,
    friend: [u8; 16],
    xfer_id: [u8; 16],
    status: &str,
    expires_at: Option<i64>,
    from: &[&str],
    asked_by_friend: bool,
) -> Result<(), String> {
    let xfer_hex = hex::encode(xfer_id);
    let row = db.chat_attachment(&xfer_hex).ok_or_else(not_found)?;
    let body = match offer_again_body(state, db, settings, &friend, &xfer_hex, &row).await {
        Ok(body) => body,
        Err(OfferAgainError::SourceGone(e)) => {
            // Settled, so the card stops offering a retry that cannot work.
            if db
                .reopen_chat_attachment(&xfer_hex, from, "source_gone", None)
                .unwrap_or(false)
            {
                emit_by_id(app, db, &xfer_hex);
            }
            return Err(e);
        }
        Err(OfferAgainError::Other(e)) => return Err(e),
    };
    let reopened = if asked_by_friend {
        db.reopen_chat_attachment_for_friend(&xfer_hex, from, status, expires_at)
    } else {
        db.reopen_chat_attachment(&xfer_hex, from, status, expires_at)
    }
    .map_err(|e| coded_ctx("peers_attach_failed", "Could not send that file", e))?;
    if !reopened {
        return Err(not_found());
    }
    if let Err(e) = send_offer_frames(state, settings, &friend, xfer_id, &body).await {
        let _ = db.set_chat_attachment_status(&xfer_hex, &row.status, None, None);
        emit_by_id(app, db, &xfer_hex);
        return Err(e);
    }
    record_offer_ttl(db, settings, friend, xfer_id);
    emit_by_id(app, db, &xfer_hex);
    info!(
        "Chat attachment: offered {xfer_hex} again ({} bytes) to {}",
        row.file_size,
        crate::security::short_hash(&friend),
    );
    Ok(())
}

/// The user pressed "Try again" on a transfer that ended without the file.
///
/// Sent: offer it again, as a fresh offer the friend has the usual time to
/// answer, which the friend's side takes or asks about exactly as a first
/// offer. Received: ask the sender to offer it again — an accept for a
/// transfer that broke is that request, and needs no new message — and this
/// press is the acceptance of the re-offer it brings; see [`on_reoffer`].
pub(super) async fn retry(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    settings: &AppSettings,
    xfer_id: [u8; 16],
) -> Result<(), String> {
    let xfer_hex = hex::encode(xfer_id);
    let row = db.chat_attachment(&xfer_hex).ok_or_else(not_found)?;
    let mut friend = [0u8; 16];
    hex::decode_to_slice(&row.friend_hash, &mut friend).map_err(|_| not_found())?;
    if !retryable(&row.direction, &row.status) {
        return Err(not_found());
    }
    let now = chrono::Utc::now().timestamp();
    if row.direction == "sent" {
        if let OfferPath::Later(why) = offer_path(state, settings, &friend).await? {
            // They cannot be reached right now: it waits for them like a
            // first send would, rather than failing again.
            if db.count_sent_chat_attachments(&row.friend_hash, "queued", now).unwrap_or(0)
                >= MAX_QUEUED_PER_FRIEND
            {
                return Err(queue_full());
            }
            let queued = db
                .reopen_chat_attachment(&xfer_hex, RETRYABLE_SENT, "queued", Some(now + ATTACH_QUEUE_TTL_SECS))
                .map_err(|e| coded_ctx("peers_attach_failed", "Could not send that file", e))?;
            if !queued {
                return Err(not_found());
            }
            emit_by_id(app, db, &xfer_hex);
            info!(
                "Chat attachment: queued {xfer_hex} again for {} ({why})",
                crate::security::short_hash(&friend),
            );
            return Ok(());
        }
        return reoffer(
            state,
            db,
            app,
            settings,
            friend,
            xfer_id,
            "offered",
            Some(now + ATTACH_OFFER_TTL_SECS),
            RETRYABLE_SENT,
            false,
        )
        .await;
    }
    if receive_running(state, &xfer_id) {
        return Ok(());
    }
    // The re-offer this asks for would be refused on arrival.
    if settings.chat_allowed_with(&friend) && !settings.files_allowed_from(&friend) {
        return Err(coded(
            "peers_attach_files_disabled_friend",
            "Files from this friend are turned off in your settings",
        ));
    }
    let session_port = offer_preflight(state, settings, &friend).await?;
    let ask = attach::encode_attach_reply(&xfer_id, AttachReply::Accept, Some(session_port));
    send_ext(state, &friend, EMBER_EXT_ATTACH_REPLY, &ask).await?;
    state.attach_retry_asked.retain(|_, at| now - *at < RETRY_ASK_WINDOW_SECS);
    state.attach_retry_asked.insert(xfer_id, now);
    info!(
        "Chat attachment: asked {} to offer {xfer_hex} again",
        crate::security::short_hash(&friend),
    );
    Ok(())
}

/// The friend answered an offer we made.
#[allow(clippy::too_many_arguments)]
pub(super) async fn on_reply(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    settings: &AppSettings,
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
    let now = chrono::Utc::now().timestamp();
    state
        .attach_reoffered
        .retain(|_, at| now - *at < ATTACH_OFFER_TTL_SECS);
    if reply.is_accept() && FRIEND_RETRYABLE_SENT.contains(&row.status.as_str()) {
        on_friend_retry(state, db, app, settings, friend, xfer_id, &row, now).await;
        return;
    }
    if reply.is_accept() {
        // The accept can arrive after the stream has already started — the
        // recipient dials the moment it sends the accept — so `active` is as
        // valid a starting point as `offered`. The stream that got there first
        // moved the expiry already; see `ServeProgress::note`.
        if !matches!(row.status.as_str(), "offered" | "accepted" | "active") {
            return;
        }
        let Some(expires_at) = db.chat_attachment_expiry(&xfer_hex) else {
            return;
        };
        let Some(extend) = accept_extends_grant(&row.status, expires_at, now) else {
            return;
        };
        if row.status != "offered" && state.attach_reoffered.remove(&xfer_id).is_none() {
            // An accept for a transfer already under way here, that is not
            // the answer to an offer we made again: their "Try again" on a
            // receive that broke without our hearing of it — they restarted,
            // or their cancel went down a session that had gone. They no
            // longer hold the offer, so it goes to them again; the grant
            // stays as it is.
            match offer_again_body(state, db, settings, &friend, &xfer_hex, &row).await {
                Ok(body) => {
                    if send_offer_frames(state, settings, &friend, xfer_id, &body).await.is_ok() {
                        record_offer_ttl(db, settings, friend, xfer_id);
                        state.attach_reoffered.insert(xfer_id, now);
                        info!(
                            "Chat attachment: offered {xfer_hex} again to {}, who lost it",
                            crate::security::short_hash(&friend),
                        );
                    }
                }
                Err(OfferAgainError::SourceGone(e) | OfferAgainError::Other(e)) => info!(
                    "Chat attachment: could not offer {xfer_hex} again for {}: {e}",
                    crate::security::short_hash(&friend),
                ),
            }
            return;
        }
        if extend {
            let _ = db.set_chat_attachment_expiry(&xfer_hex, now + ATTACH_GRANT_TTL_SECS);
            let _ = db.mark_chat_attachment_granted(&xfer_hex);
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
    // A re-offer the friend asked for goes out already `accepted`, and their
    // side can still turn it down: refused on arrival, declined when their
    // acceptance fell back to asking, or lapsed unanswered (sent as busy).
    let refused_reoffer = row.status == "accepted" && row.transferred == 0;
    if row.status != "offered" && !refused_reoffer {
        return;
    }
    state.attach_reoffered.remove(&xfer_id);
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

/// The friend's "Try again" on a transfer of ours that broke.
///
/// One that had its grant is offered again as already accepted, and only while
/// that grant is in date: nothing here extends it, so a friend cannot keep a
/// file readable past what the user gave it. One that broke before the grant
/// began — they could never reach us — is offered again as the first offer
/// was, so their accept grants it once, as it would have; but no later than
/// the grant could have run from when the user sent it, and on an offer's
/// lifetime only: a hold taken from then would run past that.
///
/// When it will not be offered again for good — the grant ran out, the file
/// is gone, chat with them is off — they are told, so their card stops
/// offering a retry. A passing failure leaves it for them to try later.
#[allow(clippy::too_many_arguments)]
async fn on_friend_retry(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    settings: &AppSettings,
    friend: [u8; 16],
    xfer_id: [u8; 16],
    row: &ChatAttachmentRow,
    now: i64,
) {
    let xfer_hex = hex::encode(xfer_id);
    let expires_at = db.chat_attachment_expiry(&xfer_hex).unwrap_or(0);
    let granted = db.chat_attachment_was_granted(&xfer_hex);
    let held = db.chat_attachment_was_held(&xfer_hex);
    let Some((status, offer_expiry)) =
        friend_retry_reopens(granted, held, row.attempt, row.created_at, expires_at, now)
    else {
        info!(
            "Chat attachment: {} asked for {xfer_hex} again after its grant ran out",
            crate::security::short_hash(&friend),
        );
        refuse_friend_retry(state, &friend, xfer_id, AttachCancel::User).await;
        return;
    };
    match reoffer(
        state,
        db,
        app,
        settings,
        friend,
        xfer_id,
        status,
        offer_expiry,
        FRIEND_RETRYABLE_SENT,
        true,
    )
    .await
    {
        Ok(()) => {
            // An `offered` row's accept is told apart by its status already.
            if status == "accepted" {
                state.attach_reoffered.insert(xfer_id, now);
            }
        }
        Err(e) => {
            info!(
                "Chat attachment: could not offer {xfer_hex} again for {}: {e}",
                crate::security::short_hash(&friend),
            );
            let gone = db
                .chat_attachment(&xfer_hex)
                .is_some_and(|r| r.status == "source_gone");
            if gone {
                refuse_friend_retry(state, &friend, xfer_id, AttachCancel::SourceGone).await;
            } else if !settings.chat_allowed_with(&friend) {
                refuse_friend_retry(state, &friend, xfer_id, AttachCancel::User).await;
            }
        }
    }
}

/// What a friend's "Try again" reopens one of our sends as, and with what
/// expiry; `None` when it is too late. See [`on_friend_retry`].
fn friend_retry_reopens(
    granted: bool,
    held: bool,
    attempt: u32,
    created_at: i64,
    expires_at: i64,
    now: i64,
) -> Option<(&'static str, Option<i64>)> {
    // Rows from before grants were recorded: one still on its first offer's
    // lifetime never had one. A hold is newer than that record, and moves
    // the expiry past the offer's without a grant.
    let never_granted =
        !granted && (attempt > 0 || held || expires_at <= created_at + ATTACH_OFFER_TTL_SECS);
    if never_granted {
        (now < created_at + ATTACH_GRANT_TTL_SECS).then_some(("offered", Some(now + ATTACH_OFFER_TTL_SECS)))
    } else {
        (expires_at > now).then_some(("accepted", None))
    }
}

async fn refuse_friend_retry(state: &NetworkState, friend: &[u8; 16], xfer_id: [u8; 16], reason: AttachCancel) {
    let body = attach::encode_attach_cancel(&xfer_id, reason);
    let _ = send_ext(state, friend, EMBER_EXT_ATTACH_CANCEL, &body).await;
}

/// What an accept may do to a grant: `None` once it has lapsed — a late accept
/// is not a way back into an offer nobody answered — and otherwise whether it
/// still carries the offer's short lifetime and should move to the grant's.
///
/// That is exactly a row still `offered`: the first accept, or the first
/// stream, moves it on, and only our own user puts it back (by offering again).
/// So a friend repeating the accept cannot keep a path readable indefinitely.
fn accept_extends_grant(status: &str, expires_at: i64, now: i64) -> Option<bool> {
    if expires_at <= now {
        return None;
    }
    Some(status == "offered")
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
    /// Where the stream had got to, for saying so when it stops.
    position: u64,
    size: u64,
}

impl ServeProgress {
    /// The last position the stream reported, and the file's size.
    pub(crate) fn reached(&self) -> (u64, u64) {
        (self.position, self.size)
    }

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
        self.position = position;
        self.size = size;
        if self.row.is_none() {
            let Some(row) = db.chat_attachment(&xfer_hex) else {
                return false;
            };
            // A friend reading the file has accepted it, whether or not its
            // accept has landed yet, so the grant moves to its full lifetime
            // here as well — once, like the accept: only `offered` moves it.
            if row.status == "offered" {
                let _ = db.set_chat_attachment_expiry(
                    &xfer_hex,
                    chrono::Utc::now().timestamp() + ATTACH_GRANT_TTL_SECS,
                );
                let _ = db.mark_chat_attachment_granted(&xfer_hex);
            }
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
        if self.queued_all && !delivered {
            info!(
                "Chat attachment: sent all of {} but the friend did not confirm it arrived",
                row.xfer_id
            );
        }
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

    if !settings.files_allowed_from(&friend) {
        // Chat off refuses files too, as it does for file offers; otherwise
        // the global files switch or the friend's own files setting decides.
        // Read as they are now, so a re-offer after the user switched this
        // off is refused like a first one.
        let _ = send_ext(state, &friend, EMBER_EXT_ATTACH_REPLY, &refuse(AttachReply::NotAllowed)).await;
        return;
    }
    let now = chrono::Utc::now().timestamp();
    // First, so an offer of ours that lapsed unanswered is not mistaken below
    // for one still waiting when the sender offers it again.
    prune_inbound(state, db, app, now).await;
    // A transfer id we already know is a duplicate delivery or a replay, and
    // must not overwrite what the first one became — unless it is the same
    // file offered again after that transfer ended without it.
    if state.attach_inbound.contains_key(&xfer_id) || receive_running(state, &xfer_id) {
        return;
    }
    if let Some(row) = db.chat_attachment(&xfer_hex) {
        on_reoffer(state, db, app, settings, friend, offer, peer_addr, row).await;
        return;
    }
    // Ahead of the unreachable branch below, which also leaves a row and an
    // event per offer.
    let pending = state
        .attach_inbound
        .values()
        .filter(|a| a.friend == friend)
        .count();
    if pending >= MAX_PENDING_PER_FRIEND || !admit_new_offer(&friend, now) {
        let _ = send_ext(state, &friend, EMBER_EXT_ATTACH_REPLY, &refuse(AttachReply::Busy)).await;
        return;
    }
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
            note_received_ttl(state, db, settings, friend, xfer_id);
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
    note_received_ttl(state, db, settings, friend, xfer_id);
    let size = offer.size;
    // A program, script or shortcut, or one named to pass for a document, is
    // never fetched unasked whatever its size: the bubble's warning is only
    // worth anything if the user sees it before the file is on disk.
    let risky = crate::security::is_dangerous_extension(&name);
    state.attach_inbound.insert(
        xfer_id,
        InboundAttach {
            friend,
            peer_pubkey,
            peer_addr,
            offer,
            name,
            received_at: now,
            requested: false,
            hold: InboundHold::Unnamed,
            notes_owed: 0,
        },
    );

    // Announced only once it is known to be waiting on the user: the UI treats
    // `awaiting` as "offered you a file", which is wrong for one fetched
    // without asking.
    if risky || !try_auto_accept(state, db, app, settings, friend, xfer_id, size, now).await {
        hold_for_user(state, xfer_id).await;
        emit_by_id(app, db, &xfer_hex);
    }
}

/// Ask the sender to hold an offer that now waits on the user. It still lapses
/// here on an offer's lifetime until the sender echoes the note (see
/// [`on_held`]); only then does it wait [`HELD_OFFER_WAIT_SECS`].
async fn hold_for_user(state: &mut NetworkState, xfer_id: [u8; 16]) {
    let unnamed = state
        .attach_inbound
        .get(&xfer_id)
        .is_some_and(|inbound| inbound.hold == InboundHold::Unnamed);
    if unnamed {
        let sessions = state.ember_sessions.read().await;
        name_held_offer(&mut state.attach_inbound, &sessions, &xfer_id);
    }
}

/// Send the sender of `xfer_id` the note naming it as kept for our user, and
/// mark it named. Only to a session that sent `EMBER_EXT_ATTACH_WAITS`: an
/// older sender never answers it, and lapses its grant at five minutes
/// whatever we say. Returns whether the note went; one such a session had no
/// room for is owed, and tried again on the next ticks.
///
/// Naming moves nothing here: a first note leaves the offer on its lifetime
/// from its arrival, and one named again stays on the lifetime it was put
/// back on.
fn name_held_offer(
    inbound: &mut std::collections::HashMap<[u8; 16], InboundAttach>,
    sessions: &std::collections::HashMap<[u8; 16], super::ed2k::upload::EmberSessionHandle>,
    xfer_id: &[u8; 16],
) -> bool {
    let Some(offer) = inbound.get_mut(xfer_id) else {
        return false;
    };
    let Some(session) = sessions
        .get(&offer.friend)
        .filter(|h| h.is_fresh() && h.is_secure_v2() && h.holds_offers())
    else {
        return false;
    };
    let note = build_ember_ext_frame(EMBER_EXT_ATTACH_WAITS, &attach::encode_attach_held(xfer_id));
    if session.tx.try_send(note).is_err() {
        if offer.notes_owed == 0 {
            offer.notes_owed = OWED_HOLD_TRIES;
        }
        return false;
    }
    offer.notes_owed = 0;
    if offer.hold == InboundHold::Unnamed {
        offer.hold = InboundHold::Named { since: offer.received_at };
    }
    true
}

/// Whether a receive of `xfer_id` is still running.
fn receive_running(state: &NetworkState, xfer_id: &[u8; 16]) -> bool {
    state
        .attach_fetches
        .get(xfer_id)
        .is_some_and(|(_, handle)| !handle.is_finished())
}

/// A friend offered again a file it offered us before, under the same transfer
/// id: the sender's "Try again", or its answer to ours. Reopens the same row,
/// so the conversation keeps one card for the file.
///
/// Only the same file from the same friend, and only after the transfer ended
/// without it. From there it is decided exactly as a first offer is, against
/// the settings as they are now: fetched without asking only under the user's
/// auto-accept ceiling and the friend's budget, and never for a risky file.
/// Having accepted the first attempt is not consent to this one — the user
/// may have changed their mind, or their settings, since.
///
/// The one exception is a re-offer the user asked for by pressing "Try again"
/// on this card within [`RETRY_ASK_WINDOW_SECS`]: that press accepted it. It
/// still goes through everything `accept_offer` checks, and falls back to
/// asking if any of that fails.
#[allow(clippy::too_many_arguments)]
async fn on_reoffer(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    settings: &AppSettings,
    friend: [u8; 16],
    offer: AttachOffer,
    peer_addr: Option<SocketAddr>,
    row: ChatAttachmentRow,
) {
    let xfer_id = offer.xfer_id;
    let xfer_hex = hex::encode(xfer_id);
    let same_file = row.direction == "received"
        && row.friend_hash == hex::encode(friend)
        && row.file_size == offer.size
        && db
            .chat_attachment_root(&xfer_hex)
            .is_some_and(|root| root == hex::encode(offer.root));
    if !same_file || !REOFFER_REOPENS.contains(&row.status.as_str()) || peer_addr.is_none() {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let pending = state
        .attach_inbound
        .values()
        .filter(|a| a.friend == friend)
        .count();
    if pending >= MAX_PENDING_PER_FRIEND {
        let busy = attach::encode_attach_reply(&xfer_id, AttachReply::Busy, None);
        let _ = send_ext(state, &friend, EMBER_EXT_ATTACH_REPLY, &busy).await;
        return;
    }
    let Some(peer_pubkey) = session_pubkey(state, &friend).await else {
        return;
    };
    let reopened = db
        .reopen_chat_attachment(&xfer_hex, REOFFER_REOPENS, "awaiting", Some(now + ATTACH_OFFER_TTL_SECS))
        .unwrap_or(false);
    if !reopened {
        return;
    }
    let asked_at = state.attach_retry_asked.remove(&xfer_id);
    let asked = asked_at.is_some_and(|at| now - at < RETRY_ASK_WINDOW_SECS);
    info!(
        "Chat attachment: {} offered {xfer_hex} again",
        crate::security::short_hash(&friend),
    );
    let size = offer.size;
    // The name as stored reads as a placeholder when it cannot be opened, so
    // the one offered now is checked as well.
    let risky = crate::security::is_dangerous_extension(&row.file_name)
        || crate::security::is_dangerous_extension(&crate::security::sanitize_filename(&offer.name));
    state.attach_inbound.insert(
        xfer_id,
        InboundAttach {
            friend,
            peer_pubkey,
            peer_addr,
            offer,
            name: row.file_name,
            received_at: now,
            requested: asked_at.is_some(),
            hold: InboundHold::Unnamed,
            notes_owed: 0,
        },
    );
    if asked {
        match accept_offer(state, db, app, settings, xfer_id).await {
            Ok(()) => return,
            Err(e) => info!("Chat attachment: {xfer_hex} waits for the user: {e}"),
        }
    } else if !risky && try_auto_accept(state, db, app, settings, friend, xfer_id, size, now).await {
        return;
    }
    hold_for_user(state, xfer_id).await;
    emit_by_id(app, db, &xfer_hex);
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
    let ceiling = settings.auto_accept_mb_for(&friend).saturating_mul(1024 * 1024);
    if ceiling == 0 || size > ceiling || !fetch_slot_free(state, &friend) {
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
///
/// The sender's side of a first offer lapses on its own clock, and one it
/// holds no earlier than ours (see [`HELD_OFFER_GRANT_SECS`]). A re-offer we
/// asked for with "Try again" may have gone out already accepted, which it
/// would hold until the grant ran out, so the sender hears it lapsed.
async fn prune_inbound(state: &mut NetworkState, db: &Database, app: &tauri::AppHandle, now: i64) {
    let lapsed = {
        let sessions = state.ember_sessions.read().await;
        settle_lapsed(db, &mut state.attach_inbound, &sessions, now)
    };
    emit_lapsed(app, db, &lapsed);
}

/// [`prune_inbound`] with the session map already read. Returns the offers
/// that lapsed, whose cards have to catch up.
fn settle_lapsed(
    db: &Database,
    inbound: &mut std::collections::HashMap<[u8; 16], InboundAttach>,
    sessions: &std::collections::HashMap<[u8; 16], super::ed2k::upload::EmberSessionHandle>,
    now: i64,
) -> Vec<[u8; 16]> {
    take_lapsed(inbound, now)
        .into_iter()
        .map(|(id, lapsed)| {
            let _ = db.set_chat_attachment_status(&hex::encode(id), "expired", None, None);
            if lapsed.requested {
                let body = attach::encode_attach_reply(&id, AttachReply::Busy, None);
                let _ = send_ext_over(sessions, &lapsed.friend, EMBER_EXT_ATTACH_REPLY, &body);
            }
            id
        })
        .collect()
}

fn emit_lapsed(app: &tauri::AppHandle, db: &Database, lapsed: &[[u8; 16]]) {
    for id in lapsed {
        emit_by_id(app, db, &hex::encode(id));
    }
}

/// Take out of `inbound` every offer no longer answerable at `now`.
fn take_lapsed(
    inbound: &mut std::collections::HashMap<[u8; 16], InboundAttach>,
    now: i64,
) -> Vec<([u8; 16], InboundAttach)> {
    let lapsed: Vec<[u8; 16]> = inbound
        .iter()
        .filter(|(_, a)| a.lapses_at() <= now)
        .map(|(id, _)| *id)
        .collect();
    lapsed
        .into_iter()
        .filter_map(|id| inbound.remove(&id).map(|a| (id, a)))
        .collect()
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
    prune_inbound(state, db, app, chrono::Utc::now().timestamp()).await;
    if let Some((why, row)) = why_unanswerable(&state.attach_inbound, db, &xfer_id) {
        // The card may still be drawn from before the sender said the file
        // went; it catches up as the answer is given.
        if let Some(row) = &row {
            emit_row(app, row);
        }
        return Err(why);
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

/// Why an answer to `xfer_id` can go nowhere, said from its row without a
/// dial, with the row for the card to catch up from. `None` while the offer is
/// still waiting here.
fn why_unanswerable(
    inbound: &std::collections::HashMap<[u8; 16], InboundAttach>,
    db: &Database,
    xfer_id: &[u8; 16],
) -> Option<(String, Option<ChatAttachmentRow>)> {
    if inbound.contains_key(xfer_id) {
        return None;
    }
    let row = db.chat_attachment(&hex::encode(xfer_id));
    Some((unanswerable(row.as_ref().map(|r| r.status.as_str())), row))
}

/// The address `friend`'s session is connected from now, for the dial an
/// accept makes: `None` inside for a relayed one, and `None` with no session.
/// An offer held across a session that was replaced came in on the old one,
/// whose address may be stale.
fn session_peer_addr(
    sessions: &std::collections::HashMap<[u8; 16], super::ed2k::upload::EmberSessionHandle>,
    friend: &[u8; 16],
) -> Option<Option<SocketAddr>> {
    sessions
        .get(friend)
        .filter(|h| h.is_secure_v2())
        .map(|h| h.peer_addr())
}

/// Where an accept dials, from [`session_peer_addr`] and the address the
/// offer came in on.
#[derive(Debug, PartialEq, Eq)]
enum AcceptDial {
    /// This target, reached through the session at this address. With no
    /// session it is the offer's own, and the accept then fails to send and
    /// puts the offer back.
    To(SocketAddr, Option<SocketAddr>),
    /// The session it would go out on is relayed. A passing state: the offer
    /// keeps waiting for a direct session, as it would for no session.
    Relayed,
    /// Nothing that can be dialled: the offer is over.
    Nowhere,
}

fn accept_dial(
    session: Option<Option<SocketAddr>>,
    offered_from: Option<SocketAddr>,
    quic_port: u16,
) -> AcceptDial {
    let peer_addr = match session {
        Some(None) => return AcceptDial::Relayed,
        Some(addr) => addr,
        None => offered_from,
    };
    match peer_addr.and_then(|addr| dial_target(addr.ip(), quic_port)) {
        Some(dial) => AcceptDial::To(dial, peer_addr),
        None => AcceptDial::Nowhere,
    }
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
    if !fetch_slot_free(state, &friend) {
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
    let session = session_peer_addr(&*state.ember_sessions.read().await, &inbound.friend);
    let (dial, peer_addr) = match accept_dial(session, inbound.peer_addr, inbound.offer.quic_port) {
        AcceptDial::To(dial, peer_addr) => (dial, peer_addr),
        AcceptDial::Relayed => {
            state.attach_inbound.insert(xfer_id, inbound);
            return Err(relayed());
        }
        AcceptDial::Nowhere => {
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
        }
    };
    // The port the sender punches toward, chosen for how it reaches us.
    let reply = attach::encode_attach_reply(
        &xfer_id,
        AttachReply::Accept,
        quic_port_for(state, peer_addr),
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
        tcp_dials: friend_tcp_candidates(db, &inbound.friend, peer_addr),
        xfer_id,
        size: inbound.offer.size,
        root: inbound.offer.root,
        name: inbound.name,
        download_folder: PathBuf::from(&settings.download_folder),
        cancel_tx,
        row,
    };
    let friend = ctx.friend;
    let handle = tokio::spawn(run_fetch(ctx));
    state.attach_fetches.insert(xfer_id, (friend, handle));
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
        super::ember::xfer::mark_received_from_internet(&dest);
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

/// One QUIC dial to the sender, pinned: the certificate it presents must hash
/// to the friend we accepted from, so nobody else can answer it.
async fn dial_quic(
    ctx: &FetchCtx,
    cert: &[u8],
    key: &[u8],
    attempt: u32,
) -> Result<quinn::Connection, ReceiveFailure> {
    let dialled = tokio::time::timeout(
        DIAL_TIMEOUT,
        super::ember::quic::connect_pinned(&ctx.endpoint, ctx.dial, "ember", Some((cert, key, ctx.friend))),
    )
    .await;
    match dialled {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => {
            info!(
                "Chat attachment: dial {}/{FETCH_ATTEMPTS} to {} failed: {e}",
                attempt + 1,
                ctx.dial
            );
            Err(ReceiveFailure::Unreachable(e.to_string()))
        }
        Err(_) => {
            info!(
                "Chat attachment: dial {}/{FETCH_ATTEMPTS} to {} timed out",
                attempt + 1,
                ctx.dial
            );
            Err(ReceiveFailure::Unreachable("the connection timed out".into()))
        }
    }
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
        let quic = dial_quic(ctx, &cert, &key, attempt);
        // QUIC listens on a UDP port of its own, which a setup forwarding only
        // the eD2K ports never opens. The friend's TCP listener is dialled
        // beside a QUIC dial once that has had a head start, rather than after
        // it has timed out, and only once. Also after a QUIC connection broke
        // mid-file: the path that carried it may be what failed, and a redial
        // over it can stall through every remaining attempt.
        let dialled = if !tcp_tried && !ctx.tcp_dials.is_empty() {
            tcp_tried = true;
            attach_tcp::dial_quic_or_tcp(quic, || dial_friend_tcp(ctx, &ctx.tcp_dials)).await
        } else {
            match quic.await {
                Ok(conn) => attach_tcp::Dialled::Quic(conn),
                Err(failure) => attach_tcp::Dialled::Neither(failure),
            }
        };
        let conn = match dialled {
            attach_tcp::Dialled::Quic(conn) => conn,
            attach_tcp::Dialled::Tcp((addr, parts)) => {
                if let Some(done) =
                    receive_over_tcp(ctx, part, &capability, &mut status_waited, addr, parts).await
                {
                    return done;
                }
                last = ReceiveFailure::Unreachable("the TCP fallback kept dropping".into());
                continue;
            }
            attach_tcp::Dialled::Neither(failure) => {
                last = failure;
                continue;
            }
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
        let mut verified = 0u64;
        let status_wait = next_status_wait(status_waited);
        let fetched = attach_stream::fetch_attachment_waiting(
            &mut recv,
            &mut send,
            &ctx.xfer_id,
            &capability,
            ctx.size,
            &ctx.root,
            handle,
            |progress| {
                verified = progress.verified;
                if last_emit.is_none_or(|at| at.elapsed() >= PROGRESS_INTERVAL) {
                    last_emit = Some(Instant::now());
                    emit_progress(&ctx.app, &ctx.db, &ctx.row, progress.received);
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
        note_stream_stopped(ctx, "QUIC", verified, attempt, &last);
    }
    Err(match last {
        ReceiveFailure::Unreachable(detail) if !connected => ReceiveFailure::NoRoute(detail),
        other => other,
    })
}

/// A stream that stopped before the file did, said in the default log: it is
/// the only record of why a transfer stalled, and it is on this side.
fn note_stream_stopped(ctx: &FetchCtx, carrier: &str, verified: u64, attempt: u32, why: &ReceiveFailure) {
    info!(
        "Chat attachment: {carrier} stream for {} stopped at {verified} of {} bytes (attempt {}/{FETCH_ATTEMPTS}): {why}",
        hex::encode(ctx.xfer_id),
        ctx.size,
        attempt + 1,
    );
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

/// The friend's upload listener at the first of `targets` that answers, over
/// the secure stream a friend session uses.
async fn dial_friend_tcp(
    ctx: &FetchCtx,
    targets: &[SocketAddr],
) -> Option<(SocketAddr, SecureStreamParts)> {
    let our_hash = super::ember::crypto::node_id_from_ed25519_bytes(&ctx.our_pubkey)?;
    for &addr in targets {
        match attach_tcp::dial_secure(addr, our_hash, ctx.our_pubkey, ctx.seed, ctx.friend).await {
            Ok(connected) => {
                info!("Chat attachment: reached the sender over TCP at {addr}");
                return Some((addr, connected));
            }
            Err(e) => info!("Chat attachment: TCP dial to {addr} failed: {e}"),
        }
    }
    None
}

/// The fallback when QUIC cannot connect: the friend's upload listener at
/// `reached`, starting on the stream `parts` already dialled there. `None` when
/// it only ever failed the way a network does, so the caller can go on trying
/// QUIC; otherwise how the receive ended.
async fn receive_over_tcp(
    ctx: &FetchCtx,
    part: &std::fs::File,
    capability: &[u8; 32],
    status_waited: &mut Duration,
    reached: SocketAddr,
    parts: SecureStreamParts,
) -> Option<Result<(), ReceiveFailure>> {
    let mut connected = Some(parts);
    let mut last = ReceiveFailure::Unreachable("no TCP attempt was made".into());
    for attempt in 0..FETCH_ATTEMPTS {
        let mut parts = match connected.take() {
            Some(parts) => parts,
            None => {
                tokio::time::sleep(Duration::from_secs(1u64 << attempt.min(3))).await;
                match dial_friend_tcp(ctx, &[reached]).await {
                    Some((_, parts)) => parts,
                    None => {
                        last = ReceiveFailure::Unreachable("the TCP redial failed".into());
                        continue;
                    }
                }
            }
        };
        let handle = match part.try_clone() {
            Ok(handle) => handle,
            Err(e) => return Some(Err(ReceiveFailure::Disk(e.to_string()))),
        };
        let mut last_emit: Option<Instant> = None;
        let mut verified = 0u64;
        let fetched = attach_tcp::fetch_over_tcp(
            &mut parts,
            attach::ATTACH_STREAM_MSG_TYPE,
            &ctx.xfer_id,
            capability,
            ctx.size,
            &ctx.root,
            handle,
            |progress| {
                verified = progress.verified;
                if last_emit.is_none_or(|at| at.elapsed() >= PROGRESS_INTERVAL) {
                    last_emit = Some(Instant::now());
                    emit_progress(&ctx.app, &ctx.db, &ctx.row, progress.received);
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
        note_stream_stopped(ctx, "TCP", verified, attempt, &last);
    }
    // A TCP path that only ever failed the way a network does is no verdict
    // on the transfer: the remaining QUIC retries may still get through.
    match last {
        ReceiveFailure::Unreachable(detail) => {
            info!("Chat attachment: TCP fallback gave up ({detail}); back to QUIC");
            None
        }
        other => Some(Err(other)),
    }
}

// --- Offers that wait for the user ---------------------------------------------
//
// An offer lapses after `ATTACH_OFFER_TTL_SECS` unless both ends agree, per
// offer, that it waits. They agree over `EMBER_EXT_ATTACH_WAITS`:
//
// - Empty, either way: sent by each side when a session comes up
//   (`on_friend_session`), and by a sender that has just let held offers go
//   while another session with the friend is still up. The reader marks the
//   session as one that holds offers; the receiver takes back the day from
//   every offer of the friend's it was told is held, and names each offer
//   still waiting on the user that the sender does not hold
//   (`on_friend_waits`).
// - Naming an offer, receiver to sender: "I am keeping this for my user"
//   (`name_held_offer`). The sender holds the grant (`on_held`,
//   `Database::hold_chat_attachment_offer`) and echoes the same note back.
// - Naming an offer, sender to receiver: that echo, "I hold it". Only the
//   echo moves the receiver to the day-long wait (`confirm_held`). A sender
//   that will not hold an offer that is still answerable says nothing, and
//   the receiver keeps it on its five minutes; one whose offer is over
//   answers with `AttachCancel`.
//
// Which of the two a named note is follows from which end of the offer this
// node is on. Any secure session with the friend ending — the one the session
// map routes through, one it retired, or a duplicate that never held its slot
// — releases the sender's holds and puts the receiver's back on five minutes
// from then (`on_session_ended`), since either end may have been told
// something over it the other never heard. The receiver names them again over
// the session that is left, or the next one, and the sender holds them again
// to where the first hold ended. A note or empty form the session had no room
// for is sent again on the next few half-minute ticks (`retry_owed_holds`).
// Nothing of it survives a restart.

/// Tell a friend whose session just came up that offers they make us can wait
/// for our answer, and that we want to hear again which of ours they keep.
/// Sent before the files queued for them go out, so a receiver on the same
/// build knows to keep those waiting too.
pub(super) async fn on_friend_session(state: &mut NetworkState, friend: [u8; 16]) {
    if send_ext(state, &friend, EMBER_EXT_ATTACH_WAITS, &[]).await.is_err() {
        owe_waits(&mut state.attach_waits_owed, friend);
    }
}

/// Owe `friend` an empty `EMBER_EXT_ATTACH_WAITS` that did not go, unless it
/// is owed already.
fn owe_waits(owed: &mut std::collections::HashMap<[u8; 16], u8>, friend: [u8; 16]) {
    owed.entry(friend).or_insert(OWED_HOLD_TRIES);
}

/// Send again what a session had no room for: empty forms owed to friends,
/// and notes owed for offers still waiting here. Each is tried on at most
/// [`OWED_HOLD_TRIES`] ticks; after that the next session's empty form starts
/// the round again. On the half-minute tick.
pub(super) async fn retry_owed_holds(state: &mut NetworkState) {
    let now = chrono::Utc::now().timestamp();
    let sessions = state.ember_sessions.read().await;
    retry_owed_at(&mut state.attach_waits_owed, &mut state.attach_inbound, &sessions, now);
}

fn retry_owed_at(
    waits_owed: &mut std::collections::HashMap<[u8; 16], u8>,
    inbound: &mut std::collections::HashMap<[u8; 16], InboundAttach>,
    sessions: &std::collections::HashMap<[u8; 16], super::ed2k::upload::EmberSessionHandle>,
    now: i64,
) {
    waits_owed.retain(|friend, tries| {
        if send_ext_over(sessions, friend, EMBER_EXT_ATTACH_WAITS, &[]).is_ok() {
            return false;
        }
        *tries = tries.saturating_sub(1);
        *tries > 0
    });
    let owed: Vec<[u8; 16]> = inbound
        .iter()
        .filter(|(_, a)| a.notes_owed > 0 && a.lapses_at() > now)
        .map(|(id, _)| *id)
        .collect();
    for id in owed {
        if !name_held_offer(inbound, sessions, &id) {
            if let Some(offer) = inbound.get_mut(&id) {
                offer.notes_owed = offer.notes_owed.saturating_sub(1);
            }
        }
    }
}

/// `EMBER_EXT_ATTACH_WAITS` from a friend: the empty form when `xfer_id` is
/// `None`; otherwise a note naming an offer, which is their keeping one of
/// ours or their echo for one of theirs we named.
pub(super) async fn on_held(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    friend: [u8; 16],
    xfer_id: Option<[u8; 16]>,
) {
    let Some(xfer_id) = xfer_id else {
        on_friend_waits(state, db, app, friend).await;
        return;
    };
    let xfer_hex = hex::encode(xfer_id);
    let now = chrono::Utc::now().timestamp();
    if state.attach_inbound.contains_key(&xfer_id) {
        if let Some(lapses_at) = confirm_held(&mut state.attach_inbound, &friend, &xfer_id, now) {
            let _ = db.set_chat_attachment_expiry(&xfer_hex, lapses_at);
            debug!(
                "Chat attachment: {} holds {xfer_hex}; it waits for us until {lapses_at}",
                crate::security::short_hash(&friend),
            );
        }
        return;
    }
    match answer_hold_note(db, &xfer_hex, &hex::encode(friend), now) {
        HoldAnswer::Echo(hold) => {
            let note = attach::encode_attach_held(&xfer_id);
            let _ = send_ext(state, &friend, EMBER_EXT_ATTACH_WAITS, &note).await;
            if hold != OfferHold::Standing {
                info!(
                    "Chat attachment: {} is keeping {xfer_hex} for later; holding it ({hold:?})",
                    crate::security::short_hash(&friend),
                );
                watch_held_source(state, db, friend, xfer_id);
            }
        }
        HoldAnswer::Quiet => {}
        HoldAnswer::Cancel(reason) => {
            info!(
                "Chat attachment: {} is keeping {xfer_hex}, which is over here ({reason:?})",
                crate::security::short_hash(&friend),
            );
            let body = attach::encode_attach_cancel(&xfer_id, reason);
            let _ = send_ext(state, &friend, EMBER_EXT_ATTACH_CANCEL, &body).await;
        }
    }
}

/// What a sender does with a friend's note naming an offer of ours.
#[derive(Debug, PartialEq, Eq)]
enum HoldAnswer {
    /// It is held: echo the note.
    Echo(OfferHold),
    /// Not held, but still answerable on its own lifetime, or not ours to
    /// them: nothing is said, and the receiver keeps it no longer than that.
    Quiet,
    /// It is over here: say so, so their card stops waiting on it.
    Cancel(AttachCancel),
}

fn answer_hold_note(db: &Database, xfer_hex: &str, friend_hex: &str, now: i64) -> HoldAnswer {
    let hold = db
        .hold_chat_attachment_offer(
            xfer_hex,
            friend_hex,
            now,
            now + ATTACH_OFFER_TTL_SECS,
            HELD_OFFER_GRANT_SECS,
        )
        .unwrap_or(OfferHold::Refused);
    if hold.is_held() {
        return HoldAnswer::Echo(hold);
    }
    let Some(row) = db
        .chat_attachment(xfer_hex)
        .filter(|row| row.direction == "sent" && row.friend_hash == friend_hex)
    else {
        return HoldAnswer::Quiet;
    };
    let in_date = db.chat_attachment_expiry(xfer_hex).is_some_and(|at| at > now);
    match row.status.as_str() {
        "offered" | "accepted" | "active" if in_date => HoldAnswer::Quiet,
        "queued" | "complete" => HoldAnswer::Quiet,
        "source_gone" => HoldAnswer::Cancel(AttachCancel::SourceGone),
        _ => HoldAnswer::Cancel(AttachCancel::User),
    }
}

/// The sender's echo of our note: it holds `xfer_id`, so the offer waits the
/// day here. Only for one from that friend we named and have not heard back
/// on, and not one that lapsed here meanwhile. Returns when it now lapses.
fn confirm_held(
    inbound: &mut std::collections::HashMap<[u8; 16], InboundAttach>,
    friend: &[u8; 16],
    xfer_id: &[u8; 16],
    now: i64,
) -> Option<i64> {
    let offer = inbound.get_mut(xfer_id).filter(|a| a.friend == *friend)?;
    if !matches!(offer.hold, InboundHold::Named { .. }) || offer.lapses_at() <= now {
        return None;
    }
    offer.hold = InboundHold::Held;
    Some(offer.lapses_at())
}

/// The sender's word on the offers from `friend` it said it holds no longer
/// stands at `now`: each goes back on an offer's lifetime from then, named
/// and waiting for the sender to say so again. Returns those that moved, with
/// when each now lapses.
fn unconfirm_held(
    inbound: &mut std::collections::HashMap<[u8; 16], InboundAttach>,
    friend: &[u8; 16],
    now: i64,
) -> Vec<([u8; 16], i64)> {
    inbound
        .iter_mut()
        .filter(|(_, a)| a.friend == *friend && a.hold == InboundHold::Held)
        .map(|(id, a)| {
            a.hold = InboundHold::Named { since: now };
            (*id, a.lapses_at())
        })
        .collect()
}

/// Name every offer from `friend` still waiting here that the sender does
/// not hold: ones named before, so the sender holds what it let go of, and
/// ones never named because no session that holds offers was up when they
/// came. Not one that lapsed at `now`: the sender would hold for a day an
/// offer both cards already call expired. Returns how many notes went.
fn name_unheld(
    inbound: &mut std::collections::HashMap<[u8; 16], InboundAttach>,
    sessions: &std::collections::HashMap<[u8; 16], super::ed2k::upload::EmberSessionHandle>,
    friend: &[u8; 16],
    now: i64,
) -> usize {
    let unheld: Vec<[u8; 16]> = inbound
        .iter()
        .filter(|(_, a)| a.friend == *friend && a.hold != InboundHold::Held && a.lapses_at() > now)
        .map(|(id, _)| *id)
        .collect();
    unheld
        .iter()
        .filter(|id| name_held_offer(inbound, sessions, id))
        .count()
}

fn record_lapses(db: &Database, moved: &[([u8; 16], i64)]) {
    for (xfer_id, lapses_at) in moved {
        let _ = db.set_chat_attachment_expiry(&hex::encode(xfer_id), *lapses_at);
    }
}

/// The friend's empty `EMBER_EXT_ATTACH_WAITS`: a session with them came up,
/// or they let go of what they held while one stayed up. Whatever they said
/// they hold may be what they let go, so it goes back on five minutes and is
/// named again with every other offer of theirs still waiting; their echo
/// gives the day back.
async fn on_friend_waits(state: &mut NetworkState, db: &Database, app: &tauri::AppHandle, friend: [u8; 16]) {
    let now = chrono::Utc::now().timestamp();
    let lapsed = {
        let sessions = state.ember_sessions.read().await;
        friend_waits_at(db, &mut state.attach_inbound, &sessions, &friend, now)
    };
    emit_lapsed(app, db, &lapsed);
}

/// [`on_friend_waits`] at `now`, with the session map already read. Offers
/// that lapsed go first, so none is named again. Returns those, for their
/// cards.
fn friend_waits_at(
    db: &Database,
    inbound: &mut std::collections::HashMap<[u8; 16], InboundAttach>,
    sessions: &std::collections::HashMap<[u8; 16], super::ed2k::upload::EmberSessionHandle>,
    friend: &[u8; 16],
    now: i64,
) -> Vec<[u8; 16]> {
    let lapsed = settle_lapsed(db, inbound, sessions, now);
    let moved = unconfirm_held(inbound, friend, now);
    record_lapses(db, &moved);
    name_unheld(inbound, sessions, friend, now);
    lapsed
}

/// A secure session with `friend` ended: the last one, one a newer session
/// retired, or a duplicate beside the one the session map holds. With
/// `newer_session_active` the map's session is still up. Each end of a held
/// offer was told what it holds over a session that may be gone, so both let
/// go and agree again. Ours go back on an offer's lifetime from now (an
/// accept already on its way still finds the grant), and the friend is asked
/// over the session that is left to name again what they keep. Theirs we
/// were told are held go back on it too, and are named again over that
/// session, or over the next one when its empty form arrives.
pub(super) async fn on_session_ended(
    state: &mut NetworkState,
    db: &Database,
    app: &tauri::AppHandle,
    friend: [u8; 16],
    newer_session_active: bool,
) {
    let now = chrono::Utc::now().timestamp();
    let ended = {
        let sessions = state.ember_sessions.read().await;
        session_ended_at(db, &mut state.attach_inbound, &sessions, &friend, now, newer_session_active)
    };
    emit_lapsed(app, db, &ended.lapsed);
    if !ended.released.is_empty() {
        info!(
            "Chat attachment: released {} held offer(s) to {} with a session",
            ended.released.len(),
            crate::security::short_hash(&friend),
        );
    }
    if ended.waits_owed {
        owe_waits(&mut state.attach_waits_owed, friend);
    }
}

/// What [`session_ended_at`] did.
#[derive(Debug, Default, PartialEq, Eq)]
struct SessionEnded {
    /// Offers waiting here that had lapsed, for their cards.
    lapsed: Vec<[u8; 16]>,
    /// Our offers to the friend it let go of.
    released: Vec<String>,
    /// The empty form asking the friend to name them again did not go.
    waits_owed: bool,
}

/// [`on_session_ended`] at `now`, with the session map already read.
fn session_ended_at(
    db: &Database,
    inbound: &mut std::collections::HashMap<[u8; 16], InboundAttach>,
    sessions: &std::collections::HashMap<[u8; 16], super::ed2k::upload::EmberSessionHandle>,
    friend: &[u8; 16],
    now: i64,
    newer_session_active: bool,
) -> SessionEnded {
    let lapsed = settle_lapsed(db, inbound, sessions, now);
    let released = db
        .release_held_chat_attachment_offers(Some(&hex::encode(friend)), now + ATTACH_OFFER_TTL_SECS)
        .unwrap_or_default();
    let waits_owed = newer_session_active
        && !released.is_empty()
        && send_ext_over(sessions, friend, EMBER_EXT_ATTACH_WAITS, &[]).is_err();
    let moved = unconfirm_held(inbound, friend, now);
    record_lapses(db, &moved);
    if newer_session_active {
        name_unheld(inbound, sessions, friend, now);
    }
    SessionEnded { lapsed, released, waits_owed }
}

/// What a look at a held offer's file found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HeldLook {
    /// No longer an offer of ours waiting on the friend (answered,
    /// cancelled, lapsed): it stops being watched.
    NotWaiting,
    Found(HeldSource),
    /// The look did not finish: the next tick tries again.
    Failed,
}

/// One look, posted back to the network loop through
/// `NetworkState::attach_held_tx`.
pub(crate) struct HeldLooked {
    xfer_id: [u8; 16],
    look: HeldLook,
}

/// Start watching the file of an offer whose hold just started or resumed,
/// against the root it was offered under (see
/// [`attach_stream::check_held_source`]), unless it is watched already.
fn watch_held_source(state: &mut NetworkState, db: &Arc<Database>, friend: [u8; 16], xfer_id: [u8; 16]) {
    state.attach_held_sources.entry(xfer_id).or_insert(HeldWatch {
        friend,
        last: None,
        gone_once: false,
    });
    start_held_look(state, db, xfer_id);
}

/// Look again at the file of every held offer, so the friend hears at once of
/// one that changed or went and their card says so before they press Accept.
/// On the half-minute tick: the stream would catch it too, but only after a
/// dial the user waited on.
pub(super) fn check_held_sources(state: &mut NetworkState, db: &Arc<Database>) {
    let held: Vec<[u8; 16]> = state.attach_held_sources.keys().copied().collect();
    for xfer_id in held {
        start_held_look(state, db, xfer_id);
    }
}

/// Look at one held offer's file on the blocking pool, unless a look at it is
/// still running: a file on a share that is asleep holds up only its own
/// look, never the network task or the next tick's. The entry stays in the
/// map while it runs, so a look that fails leaves it watched.
fn start_held_look(state: &mut NetworkState, db: &Arc<Database>, xfer_id: [u8; 16]) {
    let Some(last) = state.attach_held_sources.get(&xfer_id).map(|watch| watch.last.clone()) else {
        return;
    };
    if !state.attach_held_looking.insert(xfer_id) {
        return;
    }
    let db = db.clone();
    let report = state.attach_held_tx.clone();
    tokio::spawn(async move {
        let look = tokio::task::spawn_blocking(move || look_at_held(&db, &xfer_id, last.as_ref()))
            .await
            .unwrap_or(HeldLook::Failed);
        let _ = report.send(HeldLooked { xfer_id, look });
    });
}

/// [`attach_stream::check_held_source`] for one held offer, reading the file
/// when that is what it takes to decide: its stamp moved, or the hash cache
/// has no tree to compare the first look with. Blocking.
fn look_at_held(db: &Database, xfer_id: &[u8; 16], last: Option<&SourceStamp>) -> HeldLook {
    let xfer_hex = hex::encode(xfer_id);
    let waiting = db
        .chat_attachment(&xfer_hex)
        .is_some_and(|row| row.direction == "sent" && row.status == "offered");
    let Some((path, size, root_hex)) = waiting.then(|| db.chat_attachment_source(&xfer_hex)).flatten()
    else {
        return HeldLook::NotWaiting;
    };
    let mut root = [0u8; 32];
    if hex::decode_to_slice(&root_hex, &mut root).is_err() {
        return HeldLook::NotWaiting;
    }
    let path = PathBuf::from(path);
    HeldLook::Found(match attach_stream::check_held_source(&path, size, &root, last) {
        HeldSource::Checking => {
            attach_stream::prewarm_attachment_hash(&path);
            attach_stream::check_held_source(&path, size, &root, last)
        }
        found => found,
    })
}

/// A look at a held offer's file, back on the network task.
///
/// A file found changed or gone by two looks in a row (see
/// [`note_held_look`]) settles the offer as `source_gone` only while it is
/// still `offered`, and the friend is told. One the friend accepted
/// meanwhile is left to its stream, which refuses a changed file itself;
/// settling it here would cut a transfer that may be serving the file as
/// offered.
pub(super) async fn apply_held_look(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app: &tauri::AppHandle,
    looked: HeldLooked,
) {
    let HeldLooked { xfer_id, look } = looked;
    let Some(friend) = note_held_look(
        &mut state.attach_held_sources,
        &mut state.attach_held_looking,
        xfer_id,
        look,
    ) else {
        return;
    };
    let xfer_hex = hex::encode(xfer_id);
    if !settle_held_source_gone(db, &xfer_hex) {
        return;
    }
    emit_by_id(app, db, &xfer_hex);
    info!(
        "Chat attachment: the file for held {xfer_hex} changed or went; told {}",
        crate::security::short_hash(&friend),
    );
    let body = attach::encode_attach_cancel(&xfer_id, AttachCancel::SourceGone);
    let _ = send_ext(state, &friend, EMBER_EXT_ATTACH_CANCEL, &body).await;
}

/// Held offers being watched.
pub(crate) type HeldSources = std::collections::HashMap<[u8; 16], HeldWatch>;

/// One held offer being watched.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HeldWatch {
    /// The friend it is held for.
    friend: [u8; 16],
    /// How its file looked when last settled.
    last: Option<SourceStamp>,
    /// The last look that settled anything found it gone. One such look is
    /// not enough: over a day of half-minute looks, some catch a save midway
    /// through deleting and renaming, or truncating and writing.
    gone_once: bool,
}

/// Bring the watch up to date with a look at `xfer_id`'s file. Returns the
/// friend to tell when the file changed or went, by two settling looks in a
/// row, which are a tick apart; it stops being watched then, as it does once
/// the offer is no longer waiting. Anything that settles nothing — a look
/// that failed, a file being read or out of reach — leaves the watch as it
/// was for the next tick.
fn note_held_look(
    sources: &mut HeldSources,
    looking: &mut std::collections::HashSet<[u8; 16]>,
    xfer_id: [u8; 16],
    look: HeldLook,
) -> Option<[u8; 16]> {
    looking.remove(&xfer_id);
    match look {
        HeldLook::NotWaiting => {
            sources.remove(&xfer_id);
            None
        }
        HeldLook::Failed | HeldLook::Found(HeldSource::Checking | HeldSource::Unreadable) => None,
        HeldLook::Found(HeldSource::Unchanged(stamp)) => {
            if let Some(watch) = sources.get_mut(&xfer_id) {
                watch.last = Some(stamp);
                watch.gone_once = false;
            }
            None
        }
        HeldLook::Found(HeldSource::Gone) => {
            let watch = sources.get_mut(&xfer_id)?;
            if !watch.gone_once {
                watch.gone_once = true;
                return None;
            }
            sources.remove(&xfer_id).map(|watch| watch.friend)
        }
    }
}

fn settle_held_source_gone(db: &Database, xfer_hex: &str) -> bool {
    db.reopen_chat_attachment(xfer_hex, &["offered"], "source_gone", None)
        .unwrap_or(false)
}

// --- Either side ---------------------------------------------------------------

/// Stop whatever this node is doing for `xfer_id` and clear its part file.
fn stop_local(state: &mut NetworkState, settings: &AppSettings, xfer_id: &[u8; 16]) {
    state.attach_inbound.remove(xfer_id);
    if let Some((_, handle)) = state.attach_fetches.remove(xfer_id) {
        handle.abort();
        // The aborted task never reaches its own cleanup. Removing a link by
        // name removes the link, not what it points at, so a planted symlink
        // here cannot turn this into a delete elsewhere. Every download
        // folder, because the receive may have started before the last change.
        remove_part_files(&settings.download_roots(), xfer_id);
    }
}

fn remove_part_files(download_folders: &[String], xfer_id: &[u8; 16]) {
    for folder in download_folders {
        let part = PathBuf::from(folder)
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
    stop_local(state, settings, &xfer_id);
    let mut friend = [0u8; 16];
    // A queued file was never offered, so there is nothing to tell them.
    let told = row.status != "queued";
    if cancelled && told && hex::decode_to_slice(&row.friend_hash, &mut friend).is_ok() {
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
    let status = cancelled_as(&row.direction, &row.status, reason);
    info!(
        "Chat attachment: {} stopped {xfer_hex} ({reason:?})",
        crate::security::short_hash(&friend),
    );
    let mut moved = db
        .advance_chat_attachment(&xfer_hex, status, None, None)
        .unwrap_or(false);
    // The answer to our "Try again" on a receive that had already ended: the
    // sender will not offer it again, so the card stops offering a retry.
    if !moved
        && row.direction == "received"
        && matches!(reason, AttachCancel::User | AttachCancel::SourceGone)
    {
        state.attach_retry_asked.remove(&xfer_id);
        moved = db
            .reopen_chat_attachment(&xfer_hex, RETRYABLE_RECEIVED, status, None)
            .unwrap_or(false);
    }
    stop_local(state, settings, &xfer_id);
    if moved {
        emit_by_id(app, db, &xfer_hex);
    }
}

/// What a friend's cancel settles our row as.
///
/// An offer still waiting on us was withdrawn, whatever the sender calls it:
/// settling it as `failed` would make it look like a receive that broke. The
/// one exception is a file the sender says is gone, which a held offer is told
/// of before anyone presses Accept, and the card should say so.
fn cancelled_as(direction: &str, status: &str, reason: AttachCancel) -> &'static str {
    match reason {
        AttachCancel::SourceGone => "source_gone",
        _ if direction == "received" && status == "awaiting" => "cancelled",
        AttachCancel::User => "cancelled",
        AttachCancel::Unreachable => "unreachable",
        AttachCancel::Stalled | AttachCancel::Corrupt => "failed",
    }
}

/// A friend was removed. Their rows went with them, which already stops our
/// grants resolving; what is left is in memory: offers of theirs waiting to be
/// accepted and receives still pulling from them.
pub(super) fn forget_friend(state: &mut NetworkState, settings: &AppSettings, friend: &[u8; 16]) {
    for xfer_id in transfers_with(&state.attach_inbound, &state.attach_fetches, friend) {
        stop_local(state, settings, &xfer_id);
    }
    state.attach_auto_log.remove(friend);
    state.attach_held_sources.retain(|_, watch| watch.friend != *friend);
    state.attach_waits_owed.remove(friend);
    NEW_OFFER_RATE.lock().remove(friend);
}

fn transfers_with(
    inbound: &std::collections::HashMap<[u8; 16], InboundAttach>,
    fetches: &std::collections::HashMap<[u8; 16], ([u8; 16], tokio::task::JoinHandle<()>)>,
    friend: &[u8; 16],
) -> Vec<[u8; 16]> {
    inbound
        .iter()
        .filter(|(_, offer)| offer.friend == *friend)
        .map(|(id, _)| *id)
        .chain(
            fetches
                .iter()
                .filter(|(_, (from, _))| from == friend)
                .map(|(id, _)| *id),
        )
        .collect()
}

/// Settle what a restart stranded.
///
/// An `awaiting` offer's details lived only in memory, so it can no longer be
/// accepted; an `active` receive was cut off mid-file and does not resume
/// across processes. Both are marked and their part files cleared, so the
/// transcript says what happened instead of showing a transfer that will never
/// move. Unanswered offers of our own keep their grant until it lapses — the
/// friend may still answer after we come back — except that one held for a
/// friend keeping it is released like any other at a session's end, back on
/// an offer's lifetime until the friend names it again over the next
/// session. A send that was cut off goes back to `accepted`, since the
/// friend's receive can resume against the same grant if it dials again.
pub(super) fn sweep_interrupted(db: &Database, download_folders: &[String]) {
    let now = chrono::Utc::now().timestamp();
    let _ = db.expire_chat_attachments(now);
    let _ = db.prune_settled_chat_attachments(now);
    let _ = db.release_held_chat_attachment_offers(None, now + ATTACH_OFFER_TTL_SECS);
    let _ = db.requeue_interrupted_outbound_chat_attachments();
    let Ok(stranded) = db.interrupted_inbound_chat_attachments() else {
        return;
    };
    for (xfer_hex, status) in stranded {
        let next = if status == "awaiting" { "expired" } else { "failed" };
        let _ = db.set_chat_attachment_status(&xfer_hex, next, None, None);
        let mut id = [0u8; 16];
        if hex::decode_to_slice(&xfer_hex, &mut id).is_ok() {
            remove_part_files(download_folders, &id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_friend_can_only_make_so_many_new_offers_per_window() {
        let friend = [0xA7u8; 16];
        let now = 1_800_000_000;
        for _ in 0..MAX_NEW_OFFERS_PER_WINDOW {
            assert!(admit_new_offer(&friend, now));
        }
        assert!(!admit_new_offer(&friend, now + 1));
        assert!(admit_new_offer(&[0xA8u8; 16], now), "another friend has its own budget");
        assert!(admit_new_offer(&friend, now + NEW_OFFER_WINDOW_SECS), "and it comes back");
    }

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
    /// late or repeated one cannot move it again. Only our own re-offer puts
    /// a row back to `offered`, which is what lets a retry be extended.
    #[test]
    fn an_accept_extends_a_grant_once_and_never_revives_one() {
        let created = 1_000;
        let offer_expiry = created + ATTACH_OFFER_TTL_SECS;
        assert_eq!(accept_extends_grant("offered", offer_expiry, created + 10), Some(true));
        assert_eq!(accept_extends_grant("offered", offer_expiry, offer_expiry), None);
        assert_eq!(accept_extends_grant("offered", offer_expiry, offer_expiry + 60), None);

        let granted = created + 10 + ATTACH_GRANT_TTL_SECS;
        for moved_on in ["accepted", "active"] {
            assert_eq!(accept_extends_grant(moved_on, granted, created + 20), Some(false));
            assert_eq!(accept_extends_grant(moved_on, granted, granted - 1), Some(false));
        }
        assert_eq!(accept_extends_grant("accepted", granted, granted), None);
    }

    /// A friend's retry may give a file the one grant it never got, but never
    /// a second one, and never a grant past what the user's offer allowed.
    #[test]
    fn a_friend_retry_grants_at_most_once_and_never_past_the_users_grant() {
        let sent = 1_000_000;
        let first_offer_lapses = sent + ATTACH_OFFER_TTL_SECS;

        // Could never reach us: offered again as the first offer was.
        let now = sent + 60;
        assert_eq!(
            friend_retry_reopens(false, false, 0, sent, first_offer_lapses, now),
            Some(("offered", Some(now + ATTACH_OFFER_TTL_SECS)))
        );
        // Still so after the offer's own lifetime, within the day.
        let later = sent + 3_600;
        assert_eq!(
            friend_retry_reopens(false, false, 0, sent, first_offer_lapses, later),
            Some(("offered", Some(later + ATTACH_OFFER_TTL_SECS)))
        );
        // But not past it.
        assert_eq!(
            friend_retry_reopens(false, false, 2, sent, first_offer_lapses, sent + ATTACH_GRANT_TTL_SECS),
            None
        );

        // Had its grant: reopened inside it, unextended.
        let grant_ends = sent + 120 + ATTACH_GRANT_TTL_SECS;
        assert_eq!(
            friend_retry_reopens(true, false, 1, sent, grant_ends, sent + 7_200),
            Some(("accepted", None))
        );
        assert_eq!(friend_retry_reopens(true, false, 1, sent, grant_ends, grant_ends), None);
        // A row from before grants were recorded whose expiry moved past the
        // offer's had one.
        assert_eq!(
            friend_retry_reopens(false, false, 0, sent, grant_ends, sent + 7_200),
            Some(("accepted", None))
        );
    }

    /// A held offer's expiry moved past the offer's without anyone accepting
    /// it. Ended unanswered on its first attempt, it is not taken for a row
    /// from before grants were recorded: a friend's retry reopens it as
    /// offered, within the day the user's send had, not as accepted.
    #[test]
    fn a_held_but_unanswered_offer_reopens_as_offered_on_a_friends_retry() {
        let sent = 1_000_000;
        let held_until = sent + 10 + HELD_OFFER_GRANT_SECS;
        let now = sent + 7_200;
        assert_eq!(
            friend_retry_reopens(false, true, 0, sent, held_until, now),
            Some(("offered", Some(now + ATTACH_OFFER_TTL_SECS)))
        );
        assert_eq!(friend_retry_reopens(false, true, 0, sent, held_until, sent + ATTACH_GRANT_TTL_SECS), None);
        assert_eq!(
            friend_retry_reopens(true, true, 0, sent, held_until, now),
            Some(("accepted", None)),
            "one accepted while held had its grant"
        );

        let (db, path) = attach_db("friend-retry-held");
        let (receiver_hex, at) = ("6b".repeat(16), 2_000_000);
        let (sent_id, _) = offer_both_ends(&db, ("ec", "fc"), &receiver_hex, at);
        assert_eq!(
            answer_hold_note(&db, &sent_id, &receiver_hex, at + 1),
            HoldAnswer::Echo(OfferHold::Started)
        );
        db.set_chat_attachment_status(&sent_id, "unreachable", None, None).expect("ended unanswered");
        let expires = db.chat_attachment_expiry(&sent_id).expect("expiry");
        let row = db.chat_attachment(&sent_id).expect("row");
        let retried = at + 3_600;
        let (status, expiry) = friend_retry_reopens(
            db.chat_attachment_was_granted(&sent_id),
            db.chat_attachment_was_held(&sent_id),
            row.attempt,
            row.created_at,
            expires,
            retried,
        )
        .expect("within the day");
        assert_eq!(status, "offered");
        assert!(db
            .reopen_chat_attachment_for_friend(&sent_id, FRIEND_RETRYABLE_SENT, status, expiry)
            .expect("reopen"));
        assert_eq!(
            answer_hold_note(&db, &sent_id, &receiver_hex, retried + 1),
            HoldAnswer::Quiet,
            "their note on the retry is not held, so their side stays on five minutes"
        );
        assert_eq!(db.chat_attachment_expiry(&sent_id), Some(retried + ATTACH_OFFER_TTL_SECS));
        drop_attach_db(db, path);
    }

    /// What "Try again" is offered on: an ended send our user can re-offer, and
    /// an ended receive the sender will honour a request for.
    #[test]
    fn try_again_is_offered_only_where_it_can_work() {
        for status in ["failed", "unreachable", "busy", "expired"] {
            assert!(retryable("sent", status), "sent {status}");
        }
        for status in ["failed", "unreachable"] {
            assert!(retryable("received", status), "received {status}");
        }
        for status in ["expired", "busy", "declined", "cancelled", "complete", "source_gone"] {
            assert!(!retryable("received", status), "received {status}");
        }
        for status in ["offered", "accepted", "active", "declined", "cancelled", "complete", "too_large", "not_allowed", "source_gone"] {
            assert!(!retryable("sent", status), "sent {status}");
        }
        // A friend may only ask for what broke, which our own retry covers.
        for status in FRIEND_RETRYABLE_SENT {
            assert!(RETRYABLE_SENT.contains(status));
        }
        for status in RETRYABLE_RECEIVED {
            assert!(REOFFER_REOPENS.contains(status));
        }
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
            attempt: 0,
        }
    }

    #[test]
    fn only_a_finished_received_file_can_be_opened() {
        assert!(ChatAttachmentInfo::from_row(&row("complete", "received", Some("x"))).has_file);
        assert!(!ChatAttachmentInfo::from_row(&row("complete", "sent", Some("x"))).has_file);
        assert!(!ChatAttachmentInfo::from_row(&row("active", "received", Some("x"))).has_file);
        assert!(!ChatAttachmentInfo::from_row(&row("complete", "received", None)).has_file);
    }

    /// The card warns before anything is opened, from the same list the open
    /// path refuses to launch.
    #[test]
    fn a_program_or_a_disguised_one_is_flagged_risky() {
        let named = |name: &str| {
            let mut r = row("awaiting", "received", None);
            r.file_name = name.into();
            ChatAttachmentInfo::from_row(&r).risky
        };
        assert!(named("setup.exe"));
        assert!(named("report.pdf.exe"));
        assert!(named("invoice.pdf.LNK"));
        assert!(!named("holiday.jpg"));
        assert!(!named("notes.txt"));
    }

    #[tokio::test]
    async fn removing_a_friend_finds_their_waiting_offers_and_running_receives_only() {
        let (gone, kept) = ([1u8; 16], [2u8; 16]);
        let offer = |friend, id: u8| InboundAttach {
            friend,
            peer_pubkey: [0; 32],
            peer_addr: None,
            offer: AttachOffer {
                xfer_id: [id; 16],
                size: 1,
                root: [0; 32],
                quic_port: 1,
                name: "f".into(),
            },
            name: "f".into(),
            received_at: 0,
            requested: false,
            hold: InboundHold::Unnamed,
            notes_owed: 0,
        };
        let inbound = std::collections::HashMap::from([
            ([10u8; 16], offer(gone, 10)),
            ([11u8; 16], offer(kept, 11)),
        ]);
        let fetches = std::collections::HashMap::from([
            ([20u8; 16], (gone, tokio::spawn(async {}))),
            ([21u8; 16], (kept, tokio::spawn(async {}))),
        ]);
        let mut found = transfers_with(&inbound, &fetches, &gone);
        found.sort();
        assert_eq!(found, vec![[10u8; 16], [20u8; 16]]);
    }

    fn attach_db(tag: &str) -> (Database, PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "ember-chat-attach-{tag}-{}-{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_file(&path);
        (Database::open_at(&path).expect("open db"), path)
    }

    fn drop_attach_db(db: Database, path: PathBuf) {
        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    use crate::network::ed2k::upload::{attach_event_from_ext, EmberSessionHandle, UploadEventKind};
    use std::collections::{HashMap, HashSet};

    type Sessions = HashMap<[u8; 16], EmberSessionHandle>;

    /// Both ends of one offer made at `at`, on an offer's lifetime, as each
    /// records it: the sender's row and the receiver's waiting one. One
    /// database holds both, so each gets an id of its own.
    fn offer_both_ends(db: &Database, ids: (&str, &str), friend: &str, at: i64) -> (String, String) {
        let (sent, received) = (ids.0.repeat(16), ids.1.repeat(16));
        for (xfer, direction, status, source) in [
            (&sent, "sent", "offered", Some("C:\\private\\f.bin")),
            (&received, "received", "awaiting", None),
        ] {
            db.upsert_chat_attachment(
                xfer,
                friend,
                direction,
                "f.bin",
                10,
                &"33".repeat(32),
                source,
                status,
                at,
                at + ATTACH_OFFER_TTL_SECS,
            )
            .expect("insert");
        }
        (sent, received)
    }

    fn id_of(hex_id: &str) -> [u8; 16] {
        let mut id = [0u8; 16];
        hex::decode_to_slice(hex_id, &mut id).expect("hex id");
        id
    }

    /// The receiver's waiting offer from `sender`, as `on_offer` leaves it,
    /// having come in on a session from `addr`.
    fn waiting_offer(sender: [u8; 16], xfer_id: [u8; 16], at: i64, addr: &str) -> InboundAttach {
        InboundAttach {
            friend: sender,
            peer_pubkey: [0; 32],
            peer_addr: Some(addr.parse().expect("addr")),
            offer: AttachOffer {
                xfer_id,
                size: 10,
                root: [0x33; 32],
                quic_port: 41330,
                name: "f.bin".into(),
            },
            name: "f.bin".into(),
            received_at: at,
            requested: false,
            hold: InboundHold::Unnamed,
            notes_owed: 0,
        }
    }

    /// The receiver's session with `sender`, from `addr`, and what goes down
    /// it. `waits` is whether the sender sent the empty form on it. Each test
    /// has a sender of its own: the mark is shared by a friend's live
    /// sessions.
    fn session_from(
        sender: [u8; 16],
        addr: &str,
        waits: bool,
    ) -> (Sessions, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let handle = EmberSessionHandle::new_secure(tx, [0x44; 32], sender)
            .with_peer_addr(Some(addr.parse().expect("addr")));
        if waits {
            handle.mark_holds_offers();
        }
        (Sessions::from([(sender, handle)]), rx)
    }

    /// The `EMBER_EXT_ATTACH_WAITS` frames that went down a session, as its
    /// reader hands them to the loop.
    fn notes_sent(wire: &mut tokio::sync::mpsc::Receiver<Vec<u8>>) -> Vec<Option<[u8; 16]>> {
        let mut notes = Vec::new();
        while let Ok(frame) = wire.try_recv() {
            match attach_event_from_ext([0; 16], &frame[6..], None) {
                Some(UploadEventKind::EmberAttachHeld { xfer_id, .. }) => notes.push(xfer_id),
                _ => panic!("not an EMBER_EXT_ATTACH_WAITS frame"),
            }
        }
        notes
    }

    /// An offer the receiver named over `sessions` and the sender held at
    /// `at + 1`, with the echo taken. Returns where the sender's hold ends.
    fn hold_both_ends(
        db: &Database,
        inbound: &mut HashMap<[u8; 16], InboundAttach>,
        sessions: &Sessions,
        (sent, xfer_id): (&str, [u8; 16]),
        (sender, receiver_hex): ([u8; 16], &str),
        at: i64,
    ) -> i64 {
        assert!(name_held_offer(inbound, sessions, &xfer_id), "named");
        assert_eq!(
            answer_hold_note(db, sent, receiver_hex, at + 1),
            HoldAnswer::Echo(OfferHold::Started)
        );
        let lapses = confirm_held(inbound, &sender, &xfer_id, at + 1).expect("the echo");
        db.set_chat_attachment_expiry(&hex::encode(xfer_id), lapses).expect("receiver keeps it");
        db.chat_attachment_expiry(sent).expect("sender's expiry")
    }

    /// The whole round, as far as it runs without a network: the receiver
    /// names the offer it leaves waiting (`hold_for_user`), the sender holds
    /// it and echoes the note (`on_held`), only the echo gives the receiver
    /// the day, and an Accept an hour later finds the offer here, the grant
    /// there, and the session's address to dial (`respond`, `accept_offer`).
    #[test]
    fn an_offer_answered_after_an_hour_still_transfers() {
        let (db, path) = attach_db("hour");
        let (sender, receiver_hex) = ([0x71; 16], "61".repeat(16));
        let at = 2_000_000;
        let (sent, received) = offer_both_ends(&db, ("e1", "f1"), &receiver_hex, at);
        let xfer_id = id_of(&received);
        let mut inbound = HashMap::from([(xfer_id, waiting_offer(sender, xfer_id, at, "203.0.113.7:4662"))]);
        let (sessions, mut wire) = session_from(sender, "203.0.113.7:4662", true);

        assert!(name_held_offer(&mut inbound, &sessions, &xfer_id));
        assert_eq!(notes_sent(&mut wire), vec![Some(xfer_id)]);
        assert_eq!(
            inbound[&xfer_id].lapses_at(),
            at + ATTACH_OFFER_TTL_SECS,
            "named is not held: still five minutes"
        );
        assert_eq!(
            answer_hold_note(&db, &sent, &receiver_hex, at + 1),
            HoldAnswer::Echo(OfferHold::Started)
        );
        let lapses = confirm_held(&mut inbound, &sender, &xfer_id, at + 1).expect("the echo");
        assert_eq!(lapses, at + HELD_OFFER_WAIT_SECS);
        db.set_chat_attachment_expiry(&received, lapses).expect("receiver keeps it");

        let answered = at + 3_600;
        assert!(take_lapsed(&mut inbound, answered).is_empty(), "still answerable here");
        assert!(db.expire_chat_attachments(answered).expect("sweep").is_empty());
        assert_eq!(db.chat_attachment(&received).expect("row").status, "awaiting");
        assert!(why_unanswerable(&inbound, &db, &xfer_id).is_none(), "the accept goes out");
        assert_eq!(
            session_peer_addr(&sessions, &sender),
            Some(Some("203.0.113.7:4662".parse().unwrap()))
        );
        assert!(
            db.chat_attachment_grant(&sent, &receiver_hex, answered).is_some(),
            "the dial that follows the accept is served"
        );
        let expiry = db.chat_attachment_expiry(&sent).expect("expiry");
        assert_eq!(accept_extends_grant("offered", expiry, answered), Some(true));
        drop_attach_db(db, path);
    }

    /// The receiver lets go first, so the last accept it can send still finds
    /// the grant; after that both cards say the offer expired.
    #[test]
    fn an_offer_answered_after_the_wait_fails_cleanly_on_both_ends() {
        let (db, path) = attach_db("lapsed");
        let (sender, receiver_hex) = ([0x72; 16], "62".repeat(16));
        let at = 2_000_000;
        let (sent, received) = offer_both_ends(&db, ("e2", "f2"), &receiver_hex, at);
        let xfer_id = id_of(&received);
        let mut inbound = HashMap::from([(xfer_id, waiting_offer(sender, xfer_id, at, "203.0.113.8:4662"))]);
        let (sessions, _wire) = session_from(sender, "203.0.113.8:4662", true);
        let sender_expiry = hold_both_ends(
            &db,
            &mut inbound,
            &sessions,
            (&sent, xfer_id),
            (sender, &receiver_hex),
            at,
        );
        let lapses = inbound[&xfer_id].lapses_at();

        let in_flight = 60;
        assert_eq!(
            accept_extends_grant("offered", sender_expiry, lapses - 1 + in_flight),
            Some(true)
        );

        assert_eq!(take_lapsed(&mut inbound, lapses).len(), 1);
        assert_eq!(db.expire_chat_attachments(lapses).expect("sweep"), vec![received.clone()]);
        assert_eq!(db.chat_attachment(&received).expect("row").status, "expired");
        let (why, _) = why_unanswerable(&inbound, &db, &xfer_id).expect("lapsed");
        assert_eq!(why, not_found(), "answered without a dial");

        assert!(sender_expiry > lapses);
        assert_eq!(db.expire_chat_attachments(sender_expiry).expect("sweep"), vec![sent.clone()]);
        assert_eq!(db.chat_attachment(&sent).expect("row").status, "expired");
        assert!(db.chat_attachment_grant(&sent, &receiver_hex, sender_expiry).is_none());
        assert_eq!(accept_extends_grant("offered", sender_expiry, sender_expiry), None);
        drop_attach_db(db, path);
    }

    /// 1.7.4 sends neither form. An offer from it is never named — its session
    /// is not marked, so `hold_for_user` sends nothing it would not read — and
    /// lapses here at five minutes. An offer to it is never named back, so
    /// nothing holds it there, and our card reads as unanswered.
    #[test]
    fn offers_to_and_from_a_build_that_never_said_it_waits_lapse_at_five_minutes() {
        let (db, path) = attach_db("old-peer");
        let (sender, receiver_hex) = ([0x73; 16], "63".repeat(16));
        let at = 2_000_000;
        let (sent, received) = offer_both_ends(&db, ("e3", "f3"), &receiver_hex, at);
        let lapsed = at + ATTACH_OFFER_TTL_SECS;

        let xfer_id = id_of(&received);
        let mut inbound = HashMap::from([(xfer_id, waiting_offer(sender, xfer_id, at, "203.0.113.9:4662"))]);
        let (sessions, mut wire) = session_from(sender, "203.0.113.9:4662", false);
        assert!(!name_held_offer(&mut inbound, &sessions, &xfer_id));
        assert!(notes_sent(&mut wire).is_empty());
        assert_eq!(inbound[&xfer_id].hold, InboundHold::Unnamed);
        assert_eq!(confirm_held(&mut inbound, &sender, &xfer_id, at + 1), None, "nor is a stray echo taken");
        assert!(take_lapsed(&mut inbound, lapsed - 1).is_empty());
        assert_eq!(take_lapsed(&mut inbound, lapsed).len(), 1);

        assert!(db.chat_attachment_grant(&sent, &receiver_hex, lapsed - 1).is_some());
        assert!(db.expire_chat_attachments(lapsed).expect("sweep").contains(&sent));
        let card = ChatAttachmentInfo::from_row(&db.chat_attachment(&sent).expect("row"));
        assert_eq!((card.direction.as_str(), card.status.as_str()), ("sent", "expired"));
        assert!(card.retryable, "and the user can send it again");
        assert!(db.chat_attachment_grant(&sent, &receiver_hex, lapsed).is_none());
        let late = db
            .hold_chat_attachment_offer(
                &sent,
                &receiver_hex,
                lapsed + 1,
                lapsed + 1 + ATTACH_OFFER_TTL_SECS,
                HELD_OFFER_GRANT_SECS,
            )
            .expect("hold");
        assert!(!late.is_held(), "a late note cannot revive it");
        drop_attach_db(db, path);
    }

    /// A sleep or a redial replaces the session an offer was held over, and
    /// each end hears of the old one's end in its own time. In either order the
    /// sender's release and the receiver's naming it again leave both holding
    /// it to where the first hold ended, and the accept dials the new
    /// session's address, not the one the offer came in on. Driven through
    /// what `on_session_ended` and `on_friend_waits` run, each end over the
    /// session it routes through.
    #[test]
    fn a_held_offer_survives_a_session_replacement_with_both_ends_agreeing() {
        let (db, path) = attach_db("replaced");
        let (sender, receiver_hex) = ([0x75; 16], "65".repeat(16));
        let receiver = id_of(&receiver_hex);
        let at = 2_000_000;
        let (sent, received) = offer_both_ends(&db, ("e6", "f6"), &receiver_hex, at);
        let xfer_id = id_of(&received);
        let mut inbound = HashMap::from([(xfer_id, waiting_offer(sender, xfer_id, at, "203.0.113.10:4662"))]);
        let (old, _old_wire) = session_from(sender, "203.0.113.10:4662", true);
        let first_end = hold_both_ends(
            &db,
            &mut inbound,
            &old,
            (&sent, xfer_id),
            (sender, &receiver_hex),
            at,
        );
        let (new, mut new_wire) = session_from(sender, "198.51.100.4:4662", true);
        let (to_receiver, mut sender_wire) = session_from(receiver, "203.0.113.20:4662", true);
        let ended = at + 3_600;

        // The sender hears first: it releases, and asks over the new session.
        let mut senders_inbound = HashMap::new();
        assert_eq!(
            session_ended_at(&db, &mut senders_inbound, &to_receiver, &receiver, ended, true),
            SessionEnded { released: vec![sent.clone()], ..SessionEnded::default() }
        );
        assert_eq!(db.chat_attachment_expiry(&sent), Some(ended + ATTACH_OFFER_TTL_SECS));
        assert_eq!(notes_sent(&mut sender_wire), vec![None], "the empty form");
        assert!(friend_waits_at(&db, &mut inbound, &new, &sender, ended).is_empty());
        assert_eq!(inbound[&xfer_id].hold, InboundHold::Named { since: ended });
        assert_eq!(db.chat_attachment_expiry(&received), Some(ended + ATTACH_OFFER_TTL_SECS));
        assert_eq!(notes_sent(&mut new_wire), vec![Some(xfer_id)]);
        assert_eq!(
            answer_hold_note(&db, &sent, &receiver_hex, ended + 1),
            HoldAnswer::Echo(OfferHold::Resumed)
        );
        assert_eq!(db.chat_attachment_expiry(&sent), Some(first_end), "to where the first hold ended");
        assert_eq!(
            confirm_held(&mut inbound, &sender, &xfer_id, ended + 1),
            Some(at + HELD_OFFER_WAIT_SECS)
        );

        // Then the receiver hears of it: back on five minutes and named again
        // over the new session, and the sender, still holding it, says so.
        assert_eq!(
            session_ended_at(&db, &mut inbound, &new, &sender, ended + 5, true),
            SessionEnded::default(),
            "nothing of its own to release, so no empty form"
        );
        assert_eq!(inbound[&xfer_id].hold, InboundHold::Named { since: ended + 5 });
        assert_eq!(notes_sent(&mut new_wire), vec![Some(xfer_id)]);
        assert_eq!(
            answer_hold_note(&db, &sent, &receiver_hex, ended + 6),
            HoldAnswer::Echo(OfferHold::Standing)
        );
        assert_eq!(
            confirm_held(&mut inbound, &sender, &xfer_id, ended + 6),
            Some(at + HELD_OFFER_WAIT_SECS)
        );
        assert!(inbound[&xfer_id].lapses_at() < first_end, "the receiver still lets go first");

        let answered = at + 5 * 3_600;
        assert!(take_lapsed(&mut inbound, answered).is_empty());
        assert!(why_unanswerable(&inbound, &db, &xfer_id).is_none());
        assert!(db.chat_attachment_grant(&sent, &receiver_hex, answered).is_some());
        let dial = session_peer_addr(&new, &sender).expect("a session").expect("direct");
        assert_eq!(dial, "198.51.100.4:4662".parse().unwrap());
        assert_ne!(Some(dial), inbound[&xfer_id].peer_addr);
        drop_attach_db(db, path);
    }

    /// Each end of a crossed pair of dials routes through the connection it
    /// dialled and reads the friend's frames on the other. The sender's dies:
    /// its own slot there, a duplicate at the receiver. The sender has no
    /// session left to ask over; the receiver hears of the end too, puts the
    /// offer back on five minutes and names it over its own dial, so the
    /// sender, which let it go, holds it again.
    #[test]
    fn a_duplicate_sessions_end_puts_both_ends_of_a_crossed_pair_back_in_step() {
        let (db, path) = attach_db("crossed");
        let (sender, receiver_hex) = ([0x7d; 16], "6f".repeat(16));
        let receiver = id_of(&receiver_hex);
        let at = 2_000_000;
        let (sent, received) = offer_both_ends(&db, ("e0", "f0"), &receiver_hex, at);
        let xfer_id = id_of(&received);
        let mut inbound = HashMap::from([(xfer_id, waiting_offer(sender, xfer_id, at, "203.0.113.60:4662"))]);
        let (receivers_dial, mut receivers_wire) = session_from(sender, "203.0.113.60:4662", true);
        let first_end = hold_both_ends(
            &db,
            &mut inbound,
            &receivers_dial,
            (&sent, xfer_id),
            (sender, &receiver_hex),
            at,
        );
        assert_eq!(notes_sent(&mut receivers_wire), vec![Some(xfer_id)]);

        let ended = at + 3_600;
        assert_eq!(
            session_ended_at(&db, &mut HashMap::new(), &Sessions::new(), &receiver, ended, false),
            SessionEnded { released: vec![sent.clone()], ..SessionEnded::default() },
            "nothing to ask over"
        );
        assert_eq!(
            session_ended_at(&db, &mut inbound, &receivers_dial, &sender, ended + 1, true),
            SessionEnded::default()
        );
        assert_eq!(inbound[&xfer_id].hold, InboundHold::Named { since: ended + 1 });
        assert_eq!(db.chat_attachment_expiry(&received), Some(ended + 1 + ATTACH_OFFER_TTL_SECS));
        assert_eq!(notes_sent(&mut receivers_wire), vec![Some(xfer_id)]);
        assert_eq!(
            answer_hold_note(&db, &sent, &receiver_hex, ended + 2),
            HoldAnswer::Echo(OfferHold::Resumed)
        );
        assert_eq!(db.chat_attachment_expiry(&sent), Some(first_end));
        assert_eq!(
            confirm_held(&mut inbound, &sender, &xfer_id, ended + 2),
            Some(at + HELD_OFFER_WAIT_SECS)
        );
        drop_attach_db(db, path);
    }

    /// An offer that lapsed here is not named again when a new session says
    /// it waits or a session ends: the sender would hold for a day an offer
    /// both cards already call expired. It is settled instead.
    #[test]
    fn a_lapsed_offer_is_settled_rather_than_named_again() {
        let (db, path) = attach_db("lapsed-rename");
        let (sender, receiver_hex) = ([0x7b; 16], "6d".repeat(16));
        let at = 2_000_000;
        let (sent, received) = offer_both_ends(&db, ("ee", "fe"), &receiver_hex, at);
        let xfer_id = id_of(&received);
        let mut inbound = HashMap::from([(xfer_id, waiting_offer(sender, xfer_id, at, "203.0.113.40:4662"))]);
        let (sessions, mut wire) = session_from(sender, "203.0.113.40:4662", true);
        assert!(name_held_offer(&mut inbound, &sessions, &xfer_id));
        assert_eq!(notes_sent(&mut wire), vec![Some(xfer_id)]);

        let lapsed = at + ATTACH_OFFER_TTL_SECS;
        let swept = db.expire_chat_attachments(lapsed + 10).expect("sweep");
        assert!(swept.contains(&sent) && swept.contains(&received), "the echo never came");
        assert_eq!(name_unheld(&mut inbound, &sessions, &sender, lapsed + 10), 0);
        assert_eq!(friend_waits_at(&db, &mut inbound, &sessions, &sender, lapsed + 20), vec![xfer_id]);
        assert!(inbound.is_empty());
        assert!(notes_sent(&mut wire).is_empty(), "not named again");
        assert_eq!(db.chat_attachment(&received).expect("row").status, "expired");
        assert_eq!(
            answer_hold_note(&db, &sent, &receiver_hex, lapsed + 21),
            HoldAnswer::Cancel(AttachCancel::User)
        );

        let mut held = waiting_offer(sender, xfer_id, at, "203.0.113.40:4662");
        held.hold = InboundHold::Held;
        inbound.insert(xfer_id, held);
        let day = at + HELD_OFFER_WAIT_SECS;
        let ended = session_ended_at(&db, &mut inbound, &sessions, &sender, day, true);
        assert_eq!(ended.lapsed, vec![xfer_id], "past its day");
        assert!(inbound.is_empty());
        assert!(notes_sent(&mut wire).is_empty());
        drop_attach_db(db, path);
    }

    /// A session to `peer` whose queue is full, as a stalled writer leaves
    /// it, marked as holding offers, and the wire that empties it.
    fn full_session(peer: [u8; 16], addr: &str) -> (Sessions, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(Vec::new()).expect("fill");
        let handle = EmberSessionHandle::new_secure(tx, [0x44; 32], peer)
            .with_peer_addr(Some(addr.parse().expect("addr")));
        handle.mark_holds_offers();
        (Sessions::from([(peer, handle)]), rx)
    }

    /// A note or an empty form the session had no room for goes again on the
    /// next ticks, and is given up after `OWED_HOLD_TRIES` of them, which
    /// leaves the next session's empty form to start the round again.
    #[test]
    fn a_note_or_empty_form_that_found_no_room_is_sent_again_a_few_times() {
        let (db, path) = attach_db("owed");
        let (sender, receiver_hex) = ([0x7a; 16], "6c".repeat(16));
        let receiver = id_of(&receiver_hex);
        let at = 2_000_000;
        let (sent, received) = offer_both_ends(&db, ("ed", "fd"), &receiver_hex, at);
        let xfer_id = id_of(&received);
        let mut inbound = HashMap::from([(xfer_id, waiting_offer(sender, xfer_id, at, "203.0.113.30:4662"))]);
        let mut waits_owed = HashMap::new();

        let (full, mut wire) = full_session(sender, "203.0.113.30:4662");
        assert!(!name_held_offer(&mut inbound, &full, &xfer_id));
        assert_eq!((inbound[&xfer_id].notes_owed, inbound[&xfer_id].hold), (OWED_HOLD_TRIES, InboundHold::Unnamed));
        retry_owed_at(&mut waits_owed, &mut inbound, &full, at + 30);
        assert_eq!(inbound[&xfer_id].notes_owed, OWED_HOLD_TRIES - 1);
        assert_eq!(wire.try_recv().expect("what filled it"), Vec::<u8>::new());
        retry_owed_at(&mut waits_owed, &mut inbound, &full, at + 60);
        assert_eq!(notes_sent(&mut wire), vec![Some(xfer_id)]);
        assert_eq!((inbound[&xfer_id].notes_owed, inbound[&xfer_id].hold), (0, InboundHold::Named { since: at }));
        retry_owed_at(&mut waits_owed, &mut inbound, &full, at + 90);
        assert!(notes_sent(&mut wire).is_empty(), "nothing more is owed");

        assert_eq!(
            answer_hold_note(&db, &sent, &receiver_hex, at + 61),
            HoldAnswer::Echo(OfferHold::Started)
        );
        let (to_receiver, mut sender_wire) = full_session(receiver, "203.0.113.31:4662");
        let mut senders_inbound = HashMap::new();
        let ended = at + 600;
        let heard = session_ended_at(&db, &mut senders_inbound, &to_receiver, &receiver, ended, true);
        assert_eq!((heard.released, heard.waits_owed), (vec![sent.clone()], true));
        owe_waits(&mut waits_owed, receiver);
        owe_waits(&mut waits_owed, receiver);
        for tick in 1..i64::from(OWED_HOLD_TRIES) {
            retry_owed_at(&mut waits_owed, &mut senders_inbound, &to_receiver, ended + 30 * tick);
        }
        assert_eq!(waits_owed.get(&receiver), Some(&1), "owed once, and one try left");
        assert_eq!(sender_wire.try_recv().expect("what filled it"), Vec::<u8>::new());
        retry_owed_at(&mut waits_owed, &mut senders_inbound, &to_receiver, ended + 120);
        assert_eq!(notes_sent(&mut sender_wire), vec![None]);
        assert!(waits_owed.is_empty());

        let (stuck, _stuck_wire) = full_session(sender, "203.0.113.30:4662");
        let mut named_again = waiting_offer(sender, xfer_id, ended, "203.0.113.30:4662");
        named_again.hold = InboundHold::Named { since: ended };
        inbound.insert(xfer_id, named_again);
        assert!(!name_held_offer(&mut inbound, &stuck, &xfer_id));
        owe_waits(&mut waits_owed, sender);
        for tick in 1..=i64::from(OWED_HOLD_TRIES) {
            retry_owed_at(&mut waits_owed, &mut inbound, &stuck, ended + 30 * tick);
        }
        assert!(waits_owed.is_empty(), "never any room: given up");
        assert_eq!(inbound[&xfer_id].notes_owed, 0);
        drop_attach_db(db, path);
    }

    /// An offer that came before the sender said it waits — its queued files
    /// go out the moment a session is up, ahead of its empty form — could not
    /// be named then, and nothing is owed for it. The empty form names it.
    #[test]
    fn an_offer_that_came_before_the_senders_empty_form_is_named_by_it() {
        let (db, path) = attach_db("unnamed");
        let (sender, receiver_hex) = ([0x7c; 16], "6e".repeat(16));
        let at = 2_000_000;
        let (sent, received) = offer_both_ends(&db, ("ef", "ff"), &receiver_hex, at);
        let xfer_id = id_of(&received);
        let mut inbound = HashMap::from([(xfer_id, waiting_offer(sender, xfer_id, at, "203.0.113.50:4662"))]);
        let (sessions, mut wire) = session_from(sender, "203.0.113.50:4662", false);
        assert!(!name_held_offer(&mut inbound, &sessions, &xfer_id));
        assert_eq!(inbound[&xfer_id].notes_owed, 0);

        sessions[&sender].mark_holds_offers();
        assert!(friend_waits_at(&db, &mut inbound, &sessions, &sender, at + 2).is_empty());
        assert_eq!(notes_sent(&mut wire), vec![Some(xfer_id)]);
        assert_eq!(inbound[&xfer_id].hold, InboundHold::Named { since: at });
        assert_eq!(inbound[&xfer_id].lapses_at(), at + ATTACH_OFFER_TTL_SECS, "named is not held");
        assert_eq!(
            answer_hold_note(&db, &sent, &receiver_hex, at + 3),
            HoldAnswer::Echo(OfferHold::Started)
        );
        assert_eq!(
            confirm_held(&mut inbound, &sender, &xfer_id, at + 3),
            Some(at + HELD_OFFER_WAIT_SECS)
        );
        drop_attach_db(db, path);
    }

    /// Accepting while the session is relayed leaves the offer waiting for a
    /// direct one, as having no session does; only an address that can never
    /// be dialled ends it.
    #[test]
    fn an_accept_over_a_relayed_session_keeps_the_offer_waiting() {
        let friend = [0x7e; 16];
        let offered: SocketAddr = "203.0.113.70:4662".parse().unwrap();
        let now_at: SocketAddr = "198.51.100.7:4662".parse().unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let relayed = Sessions::from([(
            friend,
            EmberSessionHandle::new_secure(tx, [0x44; 32], friend).via_relay(true),
        )]);
        assert_eq!(
            accept_dial(session_peer_addr(&relayed, &friend), Some(offered), 41330),
            AcceptDial::Relayed
        );
        assert_eq!(
            accept_dial(Some(Some(now_at)), Some(offered), 41330),
            AcceptDial::To("198.51.100.7:41330".parse().unwrap(), Some(now_at))
        );
        assert_eq!(
            accept_dial(None, Some(offered), 41330),
            AcceptDial::To("203.0.113.70:41330".parse().unwrap(), Some(offered))
        );
        assert_eq!(accept_dial(Some(Some(now_at)), Some(offered), 0), AcceptDial::Nowhere);
        assert_eq!(accept_dial(None, None, 41330), AcceptDial::Nowhere);
    }

    /// No session back within the five minutes a release leaves: both ends
    /// let the offer go, and a note naming it on the next session is answered
    /// with a cancel rather than an accept that would fail.
    #[test]
    fn a_held_offer_whose_session_stays_gone_lapses_on_both_ends() {
        let (db, path) = attach_db("gone-session");
        let (sender, receiver_hex) = ([0x76; 16], "66".repeat(16));
        let at = 2_000_000;
        let (sent, received) = offer_both_ends(&db, ("e7", "f7"), &receiver_hex, at);
        let xfer_id = id_of(&received);
        let mut inbound = HashMap::from([(xfer_id, waiting_offer(sender, xfer_id, at, "203.0.113.11:4662"))]);
        let (sessions, _wire) = session_from(sender, "203.0.113.11:4662", true);
        hold_both_ends(&db, &mut inbound, &sessions, (&sent, xfer_id), (sender, &receiver_hex), at);

        let ended = at + 600;
        db.release_held_chat_attachment_offers(Some(&receiver_hex), ended + ATTACH_OFFER_TTL_SECS)
            .expect("release");
        unconfirm_held(&mut inbound, &sender, ended);
        let back = ended + 2 * ATTACH_OFFER_TTL_SECS;
        assert_eq!(take_lapsed(&mut inbound, back).len(), 1, "the receiver let it go");
        assert!(db.expire_chat_attachments(back).expect("sweep").contains(&sent), "and so did the sender");
        assert_eq!(
            answer_hold_note(&db, &sent, &receiver_hex, back),
            HoldAnswer::Cancel(AttachCancel::User)
        );
        drop_attach_db(db, path);
    }

    /// A sender that will not hold says so by not echoing, and the receiver
    /// stays on five minutes. Here a "Try again" re-offer went out already
    /// accepted, the receiver's accept fell back to asking and named it, and
    /// the sender, whose row is not `offered`, does not hold it. One that is
    /// over there is answered with a cancel.
    #[test]
    fn a_refused_hold_leaves_the_receiver_on_five_minutes() {
        let (db, path) = attach_db("refused");
        let (sender, receiver_hex) = ([0x77; 16], "67".repeat(16));
        let at = 2_000_000;
        let (sent, received) = offer_both_ends(&db, ("e8", "f8"), &receiver_hex, at);
        db.set_chat_attachment_status(&sent, "accepted", None, None).expect("re-offered accepted");
        db.set_chat_attachment_expiry(&sent, at + ATTACH_GRANT_TTL_SECS).expect("its grant");
        let xfer_id = id_of(&received);
        let mut inbound = HashMap::from([(xfer_id, waiting_offer(sender, xfer_id, at, "203.0.113.12:4662"))]);
        let (sessions, mut wire) = session_from(sender, "203.0.113.12:4662", true);

        assert!(name_held_offer(&mut inbound, &sessions, &xfer_id));
        assert_eq!(notes_sent(&mut wire).len(), 1);
        assert_eq!(answer_hold_note(&db, &sent, &receiver_hex, at + 1), HoldAnswer::Quiet);
        assert_eq!(db.chat_attachment_expiry(&sent), Some(at + ATTACH_GRANT_TTL_SECS), "nothing moved");
        assert_eq!(inbound[&xfer_id].lapses_at(), at + ATTACH_OFFER_TTL_SECS);
        assert_eq!(take_lapsed(&mut inbound, at + ATTACH_OFFER_TTL_SECS).len(), 1, "five minutes");

        for (status, reason) in [
            ("cancelled", AttachCancel::User),
            ("expired", AttachCancel::User),
            ("source_gone", AttachCancel::SourceGone),
        ] {
            db.set_chat_attachment_status(&sent, status, None, None).expect("status");
            assert_eq!(
                answer_hold_note(&db, &sent, &receiver_hex, at + 2),
                HoldAnswer::Cancel(reason),
                "{status}"
            );
        }
        assert_eq!(
            answer_hold_note(&db, &sent, &"68".repeat(16), at + 2),
            HoldAnswer::Quiet,
            "not an offer of ours to them: nothing is said"
        );
        assert_eq!(answer_hold_note(&db, &received, &receiver_hex, at + 2), HoldAnswer::Quiet);
        drop_attach_db(db, path);
    }

    /// No note, however often or late, holds an offer past where its first
    /// hold ended, and no echo or resync takes the receiver past a day from
    /// the offer's arrival.
    #[test]
    fn repeated_notes_never_extend_a_hold() {
        let (db, path) = attach_db("repeats");
        let (sender, receiver_hex) = ([0x78; 16], "69".repeat(16));
        let at = 2_000_000;
        let (sent, received) = offer_both_ends(&db, ("e9", "f9"), &receiver_hex, at);
        let xfer_id = id_of(&received);
        let mut inbound = HashMap::from([(xfer_id, waiting_offer(sender, xfer_id, at, "203.0.113.13:4662"))]);
        let (sessions, _wire) = session_from(sender, "203.0.113.13:4662", true);
        let first_end = hold_both_ends(&db, &mut inbound, &sessions, (&sent, xfer_id), (sender, &receiver_hex), at);
        assert_eq!(first_end, at + 1 + HELD_OFFER_GRANT_SECS);

        for heard in [at + 2, at + 3_600, first_end - 60] {
            assert_eq!(
                answer_hold_note(&db, &sent, &receiver_hex, heard),
                HoldAnswer::Echo(OfferHold::Standing)
            );
            assert_eq!(db.chat_attachment_expiry(&sent), Some(first_end), "at {heard}");
        }
        let ended = first_end - 200;
        db.release_held_chat_attachment_offers(Some(&receiver_hex), ended + ATTACH_OFFER_TTL_SECS)
            .expect("release");
        for (heard, hold) in [(ended + 1, OfferHold::Resumed), (ended + 2, OfferHold::Standing)] {
            assert_eq!(answer_hold_note(&db, &sent, &receiver_hex, heard), HoldAnswer::Echo(hold));
            assert_eq!(db.chat_attachment_expiry(&sent), Some(first_end));
        }

        let day = at + HELD_OFFER_WAIT_SECS;
        assert_eq!(confirm_held(&mut inbound, &sender, &xfer_id, at + 2), None, "held already");
        unconfirm_held(&mut inbound, &sender, day - 10);
        assert_eq!(inbound[&xfer_id].lapses_at(), day, "five minutes from then, but not past the day");
        assert_eq!(confirm_held(&mut inbound, &sender, &xfer_id, day - 5), Some(day));
        drop_attach_db(db, path);
    }

    /// The sender's watch on a held offer finds the file edited at the same
    /// size — only its hash tells — and says so; the friend's waiting card
    /// turns to "source gone", and Accept on it is answered from the row
    /// before any dial. One the friend accepted meanwhile is left to its
    /// stream.
    #[test]
    fn an_accept_after_the_file_changed_says_source_gone_without_dialing() {
        let _own = attach_stream::isolate_hash_cache();
        let (db, path) = attach_db("source-gone");
        let (sender, receiver_hex) = ([0x79; 16], "6a".repeat(16));
        let receiver = id_of(&receiver_hex);
        let at = 2_000_000;
        let source = std::env::temp_dir().join(format!(
            "ember-chat-attach-held-{}-{}.bin",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&source, b"offered bytes").expect("write");
        let tree = attach_stream::hash_for_serving(&source).expect("hashed for the offer");
        let source_str = source.to_string_lossy().into_owned();
        let (sent, accepted, received) = ("ea".repeat(16), "eb".repeat(16), "fa".repeat(16));
        for (xfer, direction, status, from) in [
            (&sent, "sent", "offered", Some(source_str.as_str())),
            (&accepted, "sent", "accepted", Some(source_str.as_str())),
            (&received, "received", "awaiting", None),
        ] {
            db.upsert_chat_attachment(
                xfer,
                &receiver_hex,
                direction,
                "f.bin",
                13,
                &hex::encode(tree.root_hash),
                from,
                status,
                at,
                at + ATTACH_OFFER_TTL_SECS,
            )
            .expect("insert");
        }
        let held = id_of(&sent);
        assert_eq!(
            answer_hold_note(&db, &sent, &receiver_hex, at + 1),
            HoldAnswer::Echo(OfferHold::Started)
        );
        let mut sources = HeldSources::from([(held, watching(receiver))]);
        let mut looking = HashSet::from([held]);
        let first = look_at_held(&db, &held, None);
        let HeldLook::Found(HeldSource::Unchanged(stamp)) = &first else {
            panic!("the first look finds the file as offered: {first:?}");
        };
        let stamp = stamp.clone();
        assert_eq!(note_held_look(&mut sources, &mut looking, held, first), None);
        assert_eq!(
            sources[&held],
            HeldWatch { friend: receiver, last: Some(stamp.clone()), gone_once: false }
        );

        std::fs::write(&source, b"edited bytes!").expect("same-size edit");
        std::fs::File::options()
            .write(true)
            .open(&source)
            .and_then(|f| f.set_modified(std::time::SystemTime::now() + Duration::from_secs(10)))
            .expect("move mtime");
        let gone = look_at_held(&db, &held, Some(&stamp));
        assert_eq!(gone, HeldLook::Found(HeldSource::Gone), "the size alone says nothing");
        looking.insert(held);
        assert_eq!(note_held_look(&mut sources, &mut looking, held, gone), None, "one look is not enough");
        let again = look_at_held(&db, &held, Some(&stamp));
        looking.insert(held);
        assert_eq!(note_held_look(&mut sources, &mut looking, held, again), Some(receiver), "the next tick's is");
        assert!(sources.is_empty() && looking.is_empty());
        assert!(settle_held_source_gone(&db, &sent));
        assert_eq!(db.chat_attachment(&sent).expect("row").status, "source_gone");
        assert!(!settle_held_source_gone(&db, &sent), "once");
        assert!(!settle_held_source_gone(&db, &accepted), "an accepted one is left to its stream");
        assert_eq!(db.chat_attachment(&accepted).expect("row").status, "accepted");
        assert_eq!(look_at_held(&db, &id_of(&accepted), None), HeldLook::NotWaiting);
        let _ = std::fs::remove_file(&source);

        let xfer_id = id_of(&received);
        let mut inbound = HashMap::from([(xfer_id, waiting_offer(sender, xfer_id, at, "203.0.113.14:4662"))]);
        let status = cancelled_as("received", "awaiting", AttachCancel::SourceGone);
        assert_eq!(status, "source_gone");
        assert!(db.advance_chat_attachment(&received, status, None, None).expect("cancel"));
        inbound.remove(&xfer_id);
        let (why, row) = why_unanswerable(&inbound, &db, &xfer_id).expect("no dial");
        assert!(why.contains("\"peers_attach_source_gone\""), "{why}");
        assert_eq!(why, source_gone());
        assert_eq!(row.expect("the card catches up").status, "source_gone");

        for reason in [AttachCancel::User, AttachCancel::Stalled, AttachCancel::Unreachable] {
            assert_eq!(cancelled_as("received", "awaiting", reason), "cancelled", "{reason:?}");
        }
        assert_eq!(cancelled_as("received", "active", AttachCancel::Stalled), "failed");
        drop_attach_db(db, path);
    }

    /// A look that did not finish, or found the file out of reach or still
    /// being read, leaves the offer watched from its last stamp and free to be
    /// looked at again; only a file that went, or an offer no longer waiting,
    /// ends the watch.
    #[test]
    fn a_held_look_that_settles_nothing_keeps_the_offer_watched() {
        let (held, friend) = ([0x91u8; 16], [0x92u8; 16]);
        let mut sources = HeldSources::from([(held, watching(friend))]);
        let mut looking = HashSet::new();
        for look in [
            HeldLook::Failed,
            HeldLook::Found(HeldSource::Unreadable),
            HeldLook::Found(HeldSource::Checking),
        ] {
            looking.insert(held);
            assert_eq!(note_held_look(&mut sources, &mut looking, held, look), None);
            assert!(looking.is_empty(), "free for the next tick");
            assert_eq!(sources.get(&held), Some(&watching(friend)));
        }
        for settles in [None, Some(friend)] {
            assert_eq!(
                note_held_look(&mut sources, &mut looking, held, HeldLook::Found(HeldSource::Gone)),
                settles
            );
        }
        assert!(sources.is_empty());
        sources.insert(held, watching(friend));
        assert_eq!(note_held_look(&mut sources, &mut looking, held, HeldLook::NotWaiting), None);
        assert!(sources.is_empty());
    }

    fn watching(friend: [u8; 16]) -> HeldWatch {
        HeldWatch { friend, last: None, gone_once: false }
    }

    /// A save that deletes and renames, or truncates and writes, can be
    /// caught midway by one look. A look that finds the file as offered again
    /// clears it, and one that settles nothing neither counts nor clears: only
    /// two settling looks in a row that find it gone end the offer.
    #[test]
    fn one_look_caught_mid_save_does_not_settle_a_held_offer() {
        let _own = attach_stream::isolate_hash_cache();
        let source = std::env::temp_dir().join(format!(
            "ember-chat-attach-mid-save-{}-{}.bin",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&source, b"as offered").expect("write");
        let tree = attach_stream::hash_for_serving(&source).expect("hashed for the offer");
        let HeldSource::Unchanged(stamp) = attach_stream::check_held_source(&source, 10, &tree.root_hash, None)
        else {
            panic!("the file as offered");
        };
        let _ = std::fs::remove_file(&source);

        let (held, friend) = ([0x95u8; 16], [0x96u8; 16]);
        let mut sources = HeldSources::from([(held, watching(friend))]);
        let mut looking = HashSet::new();
        let mut look = |found: HeldLook| note_held_look(&mut sources, &mut looking, held, found);
        assert_eq!(look(HeldLook::Found(HeldSource::Gone)), None, "mid-save");
        assert_eq!(look(HeldLook::Found(HeldSource::Unchanged(stamp))), None, "saved as it was");
        assert_eq!(look(HeldLook::Found(HeldSource::Gone)), None, "a second save, mid-way");
        assert_eq!(look(HeldLook::Failed), None);
        assert_eq!(look(HeldLook::Found(HeldSource::Gone)), Some(friend));
        assert!(sources.is_empty());
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
