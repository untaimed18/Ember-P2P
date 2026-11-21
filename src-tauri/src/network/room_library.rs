//! Room libraries on the network task: answering members who browse ours,
//! asking theirs, and taking files from them. The codec is
//! `ember::room_library`; what our library holds is `sharing::room_library`.
//!
//! A file is fetched as a room transfer, the receive running exactly as an
//! accepted offer's does. Asking for it sends the owner a fetch under a
//! transfer id of ours; the owner readies the file and offers it under that
//! id, and the offer is taken up without a prompt, since the user asked for
//! it. Fetches wait their turn here ([`Pull`]) so a whole folder can be asked
//! for at once while no more than the room transfer cap run.
//!
//! Every check that decides whether to answer is made here, on the owner's
//! side, whatever the asker's interface showed: the room is private, the
//! frame came under its current key, the asker is on its roster and not
//! banned, we are not banned from it, our library is open to it, and the
//! asker is within its rate.
//!
//! The bookkeeping is [`LibraryState`]'s, which takes the time it is asked at
//! rather than reading the clock, so it is tested apart from the network.
//!
//! Shares the parent module's namespace through `use super::*`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::*;
use crate::commands::errors::coded;
use crate::network::ember::room_library::{
    EntryId, FetchRefusal, LibraryAnswer, LibraryKey, LibraryRequest,
};

/// How often an open library is announced to its room again, so members who
/// came online since hear of it.
const ANNOUNCE_EVERY: Duration = Duration::from_secs(4 * 60);
/// The first few announcements after a library opens or Ember starts, and an
/// attempt that could not be sent, come round sooner: the room's mesh may not
/// have formed yet to carry the first.
const ANNOUNCE_EARLY_EVERY: Duration = Duration::from_secs(40);
const ANNOUNCE_EARLY: u32 = 3;
/// How long a member's word that their library is open stands without being
/// said again: three announcements missed.
const HEARD_FOR: Duration = Duration::from_secs(13 * 60);
/// How long a browse waits for its answer.
pub(crate) const ASK_WAIT: Duration = Duration::from_secs(12);
/// How long a fetch waits for the owner to say it is readying the file.
const FETCH_ANSWER_WAIT: Duration = Duration::from_secs(30);
/// How long a file the owner is readying may take to be offered: hashing a
/// 2 GB file on a slow disk.
const FETCH_PREPARE_WAIT: Duration = Duration::from_secs(10 * 60);
/// How long a fetch the owner was too busy for, or that could not be sent,
/// waits before it is asked again, and how many times it is asked.
const FETCH_RETRY_AFTER: Duration = Duration::from_secs(20);
const FETCH_TRIES: u32 = 15;
/// Fetches one device keeps waiting at once.
const PULLS_MAX: usize = 200;
/// How long a fetch given up on is remembered, so an offer the owner was
/// already readying for it is turned down rather than prompted for.
const CANCELLED_FOR: Duration = Duration::from_secs(15 * 60);
/// Files this device readies for members at once; past it a fetch is asked
/// to come back.
const PREPARING_MAX: usize = 2;
/// Browse pages one member may ask for, per window.
const LIST_RATE: (Duration, usize) = (Duration::from_secs(10), 40);
/// Fetches one member may ask for, per window.
const FETCH_RATE: (Duration, usize) = (Duration::from_secs(60), 12);
/// How often the slower upkeep runs: lapsed announcements, rate windows, and
/// announcing our own libraries again.
const UPKEEP_EVERY: Duration = Duration::from_secs(1);

/// Where one fetch of ours stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PullStage {
    /// Waiting for a free receive, or for `not_before` after a refusal.
    Queued { not_before: Option<Instant>, tries: u32 },
    /// Asked; no answer yet.
    Asked { at: Instant, tries: u32 },
    /// The owner is readying it; the offer follows.
    Preparing { at: Instant },
}

/// A file asked for from a member's library, by the transfer id it will
/// arrive under.
#[derive(Debug, Clone)]
pub(super) struct Pull {
    pub(super) channel_id: [u8; 16],
    pub(super) peer: [u8; 32],
    file: EntryId,
    pub(super) name: String,
    pub(super) size: u64,
    download_folder: std::path::PathBuf,
    queued_at: Instant,
    stage: PullStage,
}

impl Pull {
    fn status(&self) -> &'static str {
        match self.stage {
            PullStage::Queued { .. } => "queued",
            PullStage::Asked { .. } | PullStage::Preparing { .. } => "requested",
        }
    }

    /// Asked for, so holding one of the receives the transfer cap allows.
    fn holds_a_receive(&self) -> bool {
        !matches!(self.stage, PullStage::Queued { .. })
    }
}

/// A file to fetch from a member's library. Its `Debug` leaves the name and
/// folder out, so a logged command never carries them.
pub(crate) struct PullRequest {
    pub(crate) channel_id: [u8; 16],
    pub(crate) peer: [u8; 32],
    pub(crate) file: EntryId,
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) download_folder: std::path::PathBuf,
}

impl std::fmt::Debug for PullRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PullRequest {{ size: {} }}", self.size)
    }
}

/// A browse of ours waiting on its answer.
struct Ask {
    channel_id: [u8; 16],
    peer: [u8; 32],
    tx: oneshot::Sender<Result<LibraryAnswer, String>>,
    sent_at: Instant,
}

/// What a member last said of their library.
#[derive(Debug, Clone, Copy)]
struct Heard {
    open: bool,
    said_at: i64,
    heard_at: Instant,
}

/// Work done off the loop, posted back to it.
pub(super) enum LibraryWork {
    /// A page readied for a member.
    Answer {
        channel_id: [u8; 16],
        peer: [u8; 32],
        request_id: [u8; 16],
        answer: LibraryAnswer,
    },
    /// A file readied for a member's fetch.
    Offer { offer: OutgoingXferOffer },
    /// A file that could not be readied.
    Refuse {
        channel_id: [u8; 16],
        peer: [u8; 32],
        xfer_id: [u8; 16],
        reason: FetchRefusal,
    },
    /// Taking up a fetched file's offer failed.
    AcceptFailed { xfer_id: [u8; 16], error: String },
}

/// What an offer is to the fetches of ours.
pub(super) enum OfferClaim {
    /// The file we asked for, arriving: taken up without a prompt.
    Pull(Pull),
    /// One we asked for and then gave up on: turned down.
    Cancelled,
    /// Not ours: an offer like any other.
    None,
}

pub(super) struct LibraryState {
    asks: HashMap<[u8; 16], Ask>,
    pulls: HashMap<[u8; 16], Pull>,
    cancelled: HashMap<[u8; 16], Instant>,
    heard: HashMap<([u8; 16], [u8; 32]), Heard>,
    /// When each open library was last announced, or tried to be, and how
    /// many announcements have gone out since it opened or Ember started.
    announced: HashMap<[u8; 16], (Instant, u32)>,
    list_rates: HashMap<([u8; 16], [u8; 32]), VecDeque<Instant>>,
    fetch_rates: HashMap<([u8; 16], [u8; 32]), VecDeque<Instant>>,
    /// Fetches being readied, by transfer id, with the member each is for.
    preparing: HashMap<[u8; 16], ([u8; 16], [u8; 32])>,
    /// Transfers we are sending out of a library: the room, and the file.
    serving: HashMap<[u8; 16], ([u8; 16], std::path::PathBuf)>,
    upkeep_at: Option<Instant>,
    work_tx: mpsc::UnboundedSender<LibraryWork>,
    work_rx: mpsc::UnboundedReceiver<LibraryWork>,
}

impl LibraryState {
    pub(super) fn new() -> Self {
        let (work_tx, work_rx) = mpsc::unbounded_channel();
        Self {
            asks: HashMap::new(),
            pulls: HashMap::new(),
            cancelled: HashMap::new(),
            heard: HashMap::new(),
            announced: HashMap::new(),
            list_rates: HashMap::new(),
            fetch_rates: HashMap::new(),
            preparing: HashMap::new(),
            serving: HashMap::new(),
            upkeep_at: None,
            work_tx,
            work_rx,
        }
    }

    /// Queue a fetch: the transfer id it will arrive under, and whether it is
    /// new rather than the same file from the same member already waiting.
    fn queue(&mut self, request: PullRequest, xfer_id: [u8; 16], now: Instant) -> Result<([u8; 16], bool), String> {
        if let Some((id, _)) = self.pulls.iter().find(|(_, pull)| {
            pull.channel_id == request.channel_id && pull.peer == request.peer && pull.file == request.file
        }) {
            return Ok((*id, false));
        }
        if self.pulls.len() >= PULLS_MAX {
            return Err(coded("room_library_busy", "Too many files are already waiting to download"));
        }
        let name = crate::security::sanitize_filename(&request.name);
        if name.is_empty() || request.size == 0 || request.size > ember::channel::XFER_MAX_BYTES {
            return Err(coded("channels_xfer_failed", "That file cannot be fetched"));
        }
        self.pulls.insert(
            xfer_id,
            Pull {
                channel_id: request.channel_id,
                peer: request.peer,
                file: request.file,
                name,
                size: request.size,
                download_folder: request.download_folder,
                queued_at: now,
                stage: PullStage::Queued { not_before: None, tries: 0 },
            },
        );
        Ok((xfer_id, true))
    }

    /// Give up on a fetch. A fetch already asked for is remembered, so the
    /// offer it may still bring is turned down.
    fn give_up(&mut self, xfer_id: &[u8; 16], now: Instant) -> Option<Pull> {
        let pull = self.pulls.remove(xfer_id)?;
        if pull.holds_a_receive() {
            self.cancelled.insert(*xfer_id, now);
        }
        Some(pull)
    }

    /// Fetches in a room, or from one member of it, given up on.
    fn give_up_in(&mut self, channel_id: [u8; 16], member: Option<[u8; 32]>, now: Instant) -> Vec<([u8; 16], Pull)> {
        let ids: Vec<[u8; 16]> = self
            .pulls
            .iter()
            .filter(|(_, pull)| pull.channel_id == channel_id && member.is_none_or(|m| m == pull.peer))
            .map(|(id, _)| *id)
            .collect();
        ids.into_iter()
            .filter_map(|id| self.give_up(&id, now).map(|pull| (id, pull)))
            .collect()
    }

    /// Whether an offer under `xfer_id` from `sender` in this room answers a
    /// fetch of ours. Consumes the fetch, or the memory of one given up on.
    fn claim(&mut self, channel_id: [u8; 16], sender: [u8; 32], xfer_id: [u8; 16]) -> OfferClaim {
        let ours = self
            .pulls
            .get(&xfer_id)
            .is_some_and(|pull| pull.channel_id == channel_id && pull.peer == sender && pull.holds_a_receive());
        if ours {
            if let Some(pull) = self.pulls.remove(&xfer_id) {
                return OfferClaim::Pull(pull);
            }
        }
        if self.cancelled.remove(&xfer_id).is_some() {
            return OfferClaim::Cancelled;
        }
        OfferClaim::None
    }

    /// The owner's answer to a fetch of ours. Returns the fetch and the status
    /// it moves to when that is worth showing: back in the queue, or given up.
    fn on_fetch_answer(
        &mut self,
        channel_id: [u8; 16],
        sender: [u8; 32],
        xfer_id: [u8; 16],
        answer: &LibraryAnswer,
        now: Instant,
    ) -> Option<(Pull, &'static str)> {
        let pull = self.pulls.get_mut(&xfer_id)?;
        if pull.channel_id != channel_id || pull.peer != sender || !pull.holds_a_receive() {
            return None;
        }
        match answer {
            LibraryAnswer::Preparing => {
                pull.stage = PullStage::Preparing { at: now };
                None
            }
            LibraryAnswer::Refused(FetchRefusal::Busy) => {
                let tries = match pull.stage {
                    PullStage::Asked { tries, .. } => tries,
                    _ => 0,
                };
                pull.stage = PullStage::Queued { not_before: Some(now + FETCH_RETRY_AFTER), tries };
                Some((pull.clone(), "queued"))
            }
            _ => self.give_up(&xfer_id, now).map(|pull| (pull, "unavailable")),
        }
    }

    /// Fetches whose wait has run out, given up on.
    fn lapse(&mut self, now: Instant) -> Vec<([u8; 16], Pull)> {
        self.cancelled.retain(|_, at| now.saturating_duration_since(*at) < CANCELLED_FOR);
        let lapsed: Vec<[u8; 16]> = self
            .pulls
            .iter()
            .filter(|(_, pull)| match pull.stage {
                PullStage::Asked { at, .. } => now.saturating_duration_since(at) > FETCH_ANSWER_WAIT,
                PullStage::Preparing { at } => now.saturating_duration_since(at) > FETCH_PREPARE_WAIT,
                PullStage::Queued { tries, .. } => tries >= FETCH_TRIES,
            })
            .map(|(id, _)| *id)
            .collect();
        lapsed
            .into_iter()
            .filter_map(|id| self.give_up(&id, now).map(|pull| (id, pull)))
            .collect()
    }

    fn held_receives(&self) -> usize {
        self.pulls.values().filter(|pull| pull.holds_a_receive()).count()
    }

    /// Fetches to ask for now, oldest first, at most `free` of them.
    fn due(&self, free: usize, now: Instant) -> Vec<[u8; 16]> {
        let mut due: Vec<([u8; 16], Instant)> = self
            .pulls
            .iter()
            .filter(|(_, pull)| {
                matches!(pull.stage, PullStage::Queued { not_before, .. } if not_before.is_none_or(|at| at <= now))
            })
            .map(|(id, pull)| (*id, pull.queued_at))
            .collect();
        due.sort_by_key(|(_, queued_at)| *queued_at);
        due.into_iter().take(free).map(|(id, _)| id).collect()
    }

    /// Note that a fetch was asked for, or could not be sent and waits to be
    /// tried again. Returns the fetch once it is asked for.
    fn asked(&mut self, xfer_id: &[u8; 16], sent: bool, now: Instant) -> Option<Pull> {
        let pull = self.pulls.get_mut(xfer_id)?;
        let tries = match pull.stage {
            PullStage::Queued { tries, .. } => tries + 1,
            _ => 1,
        };
        if sent {
            pull.stage = PullStage::Asked { at: now, tries };
            Some(pull.clone())
        } else {
            pull.stage = PullStage::Queued { not_before: Some(now + FETCH_RETRY_AFTER), tries };
            None
        }
    }

    /// A member's word on their library. Returns whether what is shown of it
    /// changes: it opened, or it closed after being open.
    fn hear(&mut self, channel_id: [u8; 16], member: [u8; 32], open: bool, said_at: i64, now: Instant) -> bool {
        let key = (channel_id, member);
        let was = self.heard.get(&key).copied();
        if was.is_some_and(|heard| heard.said_at > said_at) {
            return false;
        }
        self.heard.insert(key, Heard { open, said_at, heard_at: now });
        was.map(|heard| heard.open && now.saturating_duration_since(heard.heard_at) < HEARD_FOR)
            .unwrap_or(false)
            != open
    }

    /// Whether the room is due to hear again that our library is open.
    fn announce_due(&self, channel_id: [u8; 16], now: Instant) -> bool {
        self.announced.get(&channel_id).is_none_or(|(at, sent)| {
            let every = if *sent < ANNOUNCE_EARLY { ANNOUNCE_EARLY_EVERY } else { ANNOUNCE_EVERY };
            now.saturating_duration_since(*at) >= every
        })
    }

    fn note_announced(&mut self, channel_id: [u8; 16], sent: bool, now: Instant) {
        let count = self.announced.get(&channel_id).map_or(0, |(_, count)| *count);
        self.announced.insert(channel_id, (now, count + u32::from(sent)));
    }

    /// Forget a member's word. Returns whether it said open.
    fn forget(&mut self, channel_id: [u8; 16], member: [u8; 32]) -> bool {
        self.heard.remove(&(channel_id, member)).is_some_and(|heard| heard.open)
    }

    fn open_members(&self, channel_id: [u8; 16], now: Instant) -> Vec<[u8; 32]> {
        self.heard
            .iter()
            .filter(|((room, _), heard)| {
                *room == channel_id && heard.open && now.saturating_duration_since(heard.heard_at) < HEARD_FOR
            })
            .map(|((_, member), _)| *member)
            .collect()
    }

    /// Members whose word has lapsed, forgotten. Returns those that had said
    /// open.
    fn lapse_heard(&mut self, now: Instant) -> Vec<([u8; 16], [u8; 32])> {
        let lapsed: Vec<([u8; 16], [u8; 32])> = self
            .heard
            .iter()
            .filter(|(_, heard)| now.saturating_duration_since(heard.heard_at) >= HEARD_FOR)
            .map(|(key, _)| *key)
            .collect();
        lapsed
            .into_iter()
            .filter(|(room, member)| self.forget(*room, *member))
            .collect()
    }
}

fn emit_pull(app_handle: &crate::host::AppHandle, xfer_id: &[u8; 16], pull: &Pull, status: &str) {
    emit_xfer_update(app_handle, xfer_id, &pull.channel_id, &pull.peer, "receive", &pull.name, pull.size, 0, status);
}

fn emit_heard(app_handle: &crate::host::AppHandle, channel_id: &[u8; 16], member: &[u8; 32], open: bool) {
    let _ = app_handle.emit(
        "ember:room-library",
        serde_json::json!({
            "channel_id": hex::encode(channel_id),
            "member_pubkey": hex::encode(member),
            "open": open,
        }),
    );
}

async fn send_library_frame(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    channel_id: [u8; 16],
    peer: [u8; 32],
    frame: Option<Vec<u8>>,
) -> bool {
    match frame {
        Some(frame) => send_xfer_frame(socket, state, db, channel_id, peer, &frame).await,
        None => false,
    }
}

async fn send_answer(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    channel_id: [u8; 16],
    peer: [u8; 32],
    request_id: [u8; 16],
    answer: &LibraryAnswer,
) -> bool {
    let frame = LibraryKey::derive(&state.local_ed25519_seed, &peer, &channel_id).and_then(|key| {
        ember::room_library::seal_answer(&key, &channel_id, &state.local_ed25519_pubkey, &peer, &request_id, answer)
    });
    send_library_frame(socket, state, db, channel_id, peer, frame).await
}

async fn send_request(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    channel_id: [u8; 16],
    peer: [u8; 32],
    request_id: [u8; 16],
    request: &LibraryRequest,
) -> bool {
    let frame = LibraryKey::derive(&state.local_ed25519_seed, &peer, &channel_id).and_then(|key| {
        ember::room_library::seal_request(&key, &channel_id, &state.local_ed25519_pubkey, &peer, &request_id, request)
    });
    send_library_frame(socket, state, db, channel_id, peer, frame).await
}

/// Whether we may speak from our library in this room: it is private, we are
/// in it, and we are not banned from it. Owning a room overrides a ban on
/// ourselves, as it does everywhere (`commands::channels::self_banned_from`).
fn room_allows_library(
    state: &mut NetworkState,
    db: &Database,
    ch: &crate::storage::database::StoredChannel,
    channel_id: [u8; 16],
) -> bool {
    let me = state.local_ed25519_pubkey;
    ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE
        && ch.in_room_now()
        && (ch.is_owner || !channel_member_banned(state, db, channel_id, &me))
}

/// Whether `member` may be answered from our library in this room at all:
/// the room allows it, the frame came under its current key, and they are on
/// its roster and not banned.
fn may_answer(
    state: &mut NetworkState,
    db: &Database,
    ch: &crate::storage::database::StoredChannel,
    channel_id: [u8; 16],
    member: &[u8; 32],
    opened: ember::channel::OpenedUnder,
) -> bool {
    opened == ember::channel::OpenedUnder::Current
        && *member != state.local_ed25519_pubkey
        && room_allows_library(state, db, ch, channel_id)
        && channel_member_on_roster(state, db, channel_id, member)
}

/// A library frame, if `plain` is one. Returns whether it was, so the gossip
/// handler looks no further.
#[allow(clippy::too_many_arguments)]
pub(super) async fn on_library_frame(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &crate::host::AppHandle,
    ch: &crate::storage::database::StoredChannel,
    channel_id: [u8; 16],
    plain: &[u8],
    opened: ember::channel::OpenedUnder,
) -> bool {
    let Some((version, sender, target, request_id)) = ember::room_library::frame_peek(plain) else {
        return false;
    };
    if target != state.local_ed25519_pubkey || sender == target {
        return true;
    }
    let Some(key) = LibraryKey::derive(&state.local_ed25519_seed, &sender, &channel_id) else {
        return true;
    };
    if version == ember::channel::LIBRARY_REQUEST_PLAIN_VERSION {
        let Some(request) = ember::room_library::open_request(&key, &channel_id, plain) else {
            debug!("Room library: dropped a request that did not open for the member it named");
            return true;
        };
        on_request(socket, state, db, ch, channel_id, sender, request_id, request, opened).await;
    } else {
        let Some(answer) = ember::room_library::open_answer(&key, &channel_id, plain) else {
            debug!("Room library: dropped an answer that did not open for the member it named");
            return true;
        };
        on_answer(state, app_handle, channel_id, sender, request_id, answer);
    }
    true
}

#[allow(clippy::too_many_arguments)]
async fn on_request(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    ch: &crate::storage::database::StoredChannel,
    channel_id: [u8; 16],
    sender: [u8; 32],
    request_id: [u8; 16],
    request: LibraryRequest,
    opened: ember::channel::OpenedUnder,
) {
    // Someone who may not be answered is not told why, or even that the frame
    // arrived: a stranger learns nothing of a library by asking.
    if !may_answer(state, db, ch, channel_id, &sender, opened) {
        return;
    }
    let now = Instant::now();
    let (rates, (window, limit)) = match request {
        LibraryRequest::List { .. } => (&mut state.room_library.list_rates, LIST_RATE),
        LibraryRequest::Fetch { .. } => (&mut state.room_library.fetch_rates, FETCH_RATE),
    };
    if !ember::channel::rate_window_allow(rates.entry((channel_id, sender)).or_default(), now, window, limit) {
        debug!("Room library: a member is asking faster than the rate allows");
        return;
    }
    note_channel_member_alive(state, channel_id, &sender, chrono::Utc::now().timestamp());
    if !crate::sharing::room_library::is_open(&channel_id) {
        send_answer(socket, state, db, channel_id, sender, request_id, &LibraryAnswer::Closed).await;
        return;
    }
    let room = hex::encode(channel_id);
    match request {
        LibraryRequest::List { folder, offset, query } => {
            let work = state.room_library.work_tx.clone();
            tokio::spawn(async move {
                let answer = tokio::task::spawn_blocking(move || {
                    let catalog = crate::sharing::room_library::catalog(&room);
                    if query.trim().is_empty() {
                        catalog.list(folder.as_ref(), offset).map_or(LibraryAnswer::Missing, LibraryAnswer::Page)
                    } else {
                        LibraryAnswer::Page(catalog.search(&query, offset))
                    }
                })
                .await
                .unwrap_or(LibraryAnswer::Missing);
                let _ = work.send(LibraryWork::Answer { channel_id, peer: sender, request_id, answer });
            });
        }
        LibraryRequest::Fetch { file, size } => {
            let xfer_id = request_id;
            let library = &state.room_library;
            // The same fetch again, while its file is readied or sent: the
            // answer it is waiting for is already on its way. Or an id the
            // asker chose that a transfer here already goes by, in either
            // direction: the transfer maps are keyed by it, so it is not
            // offered a second time under one.
            if library.preparing.contains_key(&xfer_id)
                || library.pulls.contains_key(&xfer_id)
                || state.xfer_send.contains_key(&xfer_id)
                || state.xfer_recv.contains_key(&xfer_id)
                || state.xfer_pending.contains_key(&xfer_id)
                || state.xfer_accepting.contains_key(&xfer_id)
                || state.xfer_finishing.contains_key(&xfer_id)
            {
                return;
            }
            let serving_them = library
                .serving
                .keys()
                .filter(|id| state.xfer_send.get(*id).is_some_and(|send| send.peer == sender))
                .count()
                + library.preparing.values().filter(|(_, peer)| *peer == sender).count();
            if library.preparing.len() >= PREPARING_MAX || serving_them >= ember::channel::XFER_MAX_ACTIVE {
                let busy = LibraryAnswer::Refused(FetchRefusal::Busy);
                send_answer(socket, state, db, channel_id, sender, request_id, &busy).await;
                return;
            }
            state.room_library.preparing.insert(xfer_id, (channel_id, sender));
            send_answer(socket, state, db, channel_id, sender, request_id, &LibraryAnswer::Preparing).await;
            let work = state.room_library.work_tx.clone();
            tokio::spawn(async move {
                let readied = tokio::task::spawn_blocking(move || {
                    let (path, name) = crate::sharing::room_library::resolve_file(&room, &file, size)
                        .ok_or(FetchRefusal::Gone)?;
                    // Cached for the QUIC stream that serves it, as an offer
                    // the user makes is.
                    let tree = ember::attach_stream::hash_for_serving(&path).map_err(|_| FetchRefusal::Failed)?;
                    if tree.file_size != size {
                        return Err(FetchRefusal::Gone);
                    }
                    Ok((path, name, tree.root_hash))
                })
                .await
                .unwrap_or(Err(FetchRefusal::Failed));
                let _ = work.send(match readied {
                    Ok((path, name, root)) => LibraryWork::Offer {
                        offer: OutgoingXferOffer {
                            channel_id,
                            peer: sender,
                            xfer_id,
                            path,
                            name,
                            size,
                            root,
                        },
                    },
                    Err(reason) => LibraryWork::Refuse { channel_id, peer: sender, xfer_id, reason },
                });
            });
        }
    }
}

fn on_answer(
    state: &mut NetworkState,
    app_handle: &crate::host::AppHandle,
    channel_id: [u8; 16],
    sender: [u8; 32],
    request_id: [u8; 16],
    answer: LibraryAnswer,
) {
    let library = &mut state.room_library;
    if answer == LibraryAnswer::Closed && library.forget(channel_id, sender) {
        emit_heard(app_handle, &channel_id, &sender, false);
    }
    if library
        .asks
        .get(&request_id)
        .is_some_and(|ask| ask.channel_id == channel_id && ask.peer == sender)
    {
        if let Some(ask) = library.asks.remove(&request_id) {
            let _ = ask.tx.send(Ok(answer));
        }
        return;
    }
    if let Some((pull, status)) = library.on_fetch_answer(channel_id, sender, request_id, &answer, Instant::now()) {
        emit_pull(app_handle, &request_id, &pull, status);
    }
}

/// A member's word that their library is open to the room, or closed. Called
/// once the frame has passed the rules every extension frame meets.
pub(super) fn on_library_status(
    state: &mut NetworkState,
    db: &Database,
    app_handle: &crate::host::AppHandle,
    ch: &crate::storage::database::StoredChannel,
    gossip: &ember::channel::ChannelGossip,
    ext: &ember::channel::ChannelExtFrame,
    opened: ember::channel::OpenedUnder,
) {
    let channel_id = gossip.channel_id;
    if ext.flags != 0
        || ext.sender == state.local_ed25519_pubkey
        || ch.visibility != ember::channel::CHANNEL_KIND_PRIVATE
        || opened != ember::channel::OpenedUnder::Current
        || !channel_member_on_roster(state, db, channel_id, &ext.sender)
    {
        return;
    }
    let Some(open) = ember::room_library::decode_status(&ext.body) else {
        return;
    };
    if state
        .room_library
        .hear(channel_id, ext.sender, open, gossip.timestamp, Instant::now())
    {
        emit_heard(app_handle, &channel_id, &ext.sender, open);
    }
}

/// Members whose libraries are open to the room, as last heard.
pub(super) fn open_members(state: &NetworkState, channel_id: [u8; 16]) -> Vec<[u8; 32]> {
    state.room_library.open_members(channel_id, Instant::now())
}

/// Tell the room our library is open, or closed. Nothing when we are not
/// in it, it is not private, or we are banned from it.
async fn announce(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    channel_id: [u8; 16],
    open: bool,
) -> bool {
    let Some(view) = cached_channel_view(state, db, channel_id) else {
        return false;
    };
    if !room_allows_library(state, db, &view.row, channel_id) {
        return false;
    }
    let Some(key) = view.content_keys.first().copied() else {
        return false;
    };
    let me = state.local_ed25519_pubkey;
    let mut msg_id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut msg_id);
    let ts = chrono::Utc::now().timestamp();
    let body = ember::room_library::encode_status(open);
    let kind = ember::channel::EXT_KIND_ROOM_LIBRARY;
    let signing = ember::crypto::signing_key_from_bytes(&state.local_ed25519_seed);
    let signature = ember::channel::ext_author_signature(&signing, &channel_id, &msg_id, ts, kind, 0, &body);
    let frame = ember::channel::encode_channel_ext_frame_presigned(kind, 0, &me, &signature, &body);
    let gossip = ember::channel::ChannelGossip::sealed(
        channel_id,
        msg_id,
        &key,
        ts.max(0) as u64,
        &frame,
        ember::channel::CHANNEL_MSG_TTL_DEFAULT,
        ts,
    );
    remember_originated_gossip(state, &gossip);
    fanout_channel_gossip_body(socket, state, db, gossip.encode(), None).await;
    true
}

/// Our library in the room was opened, closed, or had a folder taken out.
/// Said to the room now, and whatever is being sent out of it that the
/// library no longer holds stops.
pub(super) async fn library_changed(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &crate::host::AppHandle,
    channel_id: [u8; 16],
) {
    let library = crate::sharing::room_library::get(&hex::encode(channel_id));
    // Opened, or changed while open: announced now, and the early round
    // starts over so members whose copy missed it hear soon.
    state.room_library.announced.remove(&channel_id);
    let sent = announce(socket, state, db, channel_id, library.open).await;
    if library.open {
        state.room_library.note_announced(channel_id, sent, Instant::now());
    }
    let folders: Vec<std::path::PathBuf> = library
        .folders
        .iter()
        .filter_map(|folder| std::path::Path::new(folder).canonicalize().ok())
        .collect();
    let stopped: Vec<[u8; 16]> = state
        .room_library
        .serving
        .iter()
        .filter(|(_, (room, path))| {
            *room == channel_id && (!library.open || !folders.iter().any(|folder| path.starts_with(folder)))
        })
        .map(|(xfer_id, _)| *xfer_id)
        .collect();
    for xfer_id in stopped {
        state.room_library.serving.remove(&xfer_id);
        let Some(send) = state.xfer_send.remove(&xfer_id) else {
            continue;
        };
        let plain = ember::channel::encode_xfer_cancel(
            &send.key,
            &state.local_ed25519_pubkey,
            &send.peer,
            &xfer_id,
            ember::channel::XferCancel::SourceGone,
        );
        send_xfer_frame(socket, state, db, send.channel_id, send.peer, &plain).await;
        emit_xfer_update(app_handle, &xfer_id, &send.channel_id, &send.peer, "send", &send.name, send.size, 0, "cancelled");
    }
}

/// Ask a member for a page of their library. The answer, or an error, comes
/// back on `tx`.
pub(super) async fn ask(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    channel_id: [u8; 16],
    peer: [u8; 32],
    request: LibraryRequest,
    tx: oneshot::Sender<Result<LibraryAnswer, String>>,
) {
    let mut request_id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut request_id);
    if !send_request(socket, state, db, channel_id, peer, request_id, &request).await {
        let _ = tx.send(Err(coded("channels_xfer_unreachable", "Could not reach that member right now")));
        return;
    }
    state.room_library.asks.insert(
        request_id,
        Ask {
            channel_id,
            peer,
            tx,
            sent_at: Instant::now(),
        },
    );
}

/// Queue a fetch. Returns the transfer id it will arrive under.
pub(super) fn queue_pull(
    state: &mut NetworkState,
    app_handle: &crate::host::AppHandle,
    request: PullRequest,
) -> Result<[u8; 16], String> {
    let xfer_id = ember::channel::mint_xfer_id(chrono::Utc::now().timestamp());
    let (xfer_id, new) = state.room_library.queue(request, xfer_id, Instant::now())?;
    if new {
        if let Some(pull) = state.room_library.pulls.get(&xfer_id) {
            emit_pull(app_handle, &xfer_id, pull, "queued");
        }
    }
    Ok(xfer_id)
}

/// Stop a fetch that has not become a receive yet. `false` when `xfer_id`
/// is not one.
pub(super) fn cancel_pull(state: &mut NetworkState, app_handle: &crate::host::AppHandle, xfer_id: &[u8; 16]) -> bool {
    let Some(pull) = state.room_library.give_up(xfer_id, Instant::now()) else {
        return false;
    };
    emit_pull(app_handle, xfer_id, &pull, "cancelled");
    true
}

/// Fetches of ours in a room left or from a member banned, which no offer
/// can come for now.
pub(super) fn drop_pulls_for(
    state: &mut NetworkState,
    app_handle: &crate::host::AppHandle,
    channel_id: [u8; 16],
    member: Option<[u8; 32]>,
    status: &str,
) {
    let library = &mut state.room_library;
    for (xfer_id, pull) in library.give_up_in(channel_id, member, Instant::now()) {
        emit_pull(app_handle, &xfer_id, &pull, status);
    }
    library
        .heard
        .retain(|(room, peer), _| !(*room == channel_id && member.is_none_or(|m| m == *peer)));
}

/// Fetches of ours, for the room's transfer list.
pub(super) fn pull_snapshots(state: &NetworkState) -> Vec<ChannelTransferSnapshot> {
    state
        .room_library
        .pulls
        .iter()
        .map(|(xfer_id, pull)| ChannelTransferSnapshot {
            xfer_id: hex::encode(xfer_id),
            channel_id: hex::encode(pull.channel_id),
            peer_pubkey: hex::encode(pull.peer),
            direction: "receive".into(),
            name: pull.name.clone(),
            size: pull.size,
            transferred: 0,
            status: pull.status().into(),
            risky: crate::security::is_dangerous_extension(&pull.name),
        })
        .collect()
}

/// Whether `offer`, from its sender in this room, is the answer to a fetch
/// of ours. Matched on the transfer id we chose, the room and the member it
/// was asked of; anything else is an ordinary offer.
pub(super) fn claim_offer(state: &mut NetworkState, channel_id: [u8; 16], offer: &ember::channel::XferOffer) -> OfferClaim {
    state.room_library.claim(channel_id, offer.sender, offer.xfer_id)
}

/// Take up the offer of a file we fetched: the receive starts as an accepted
/// offer's does, without asking. It still has to be from a member the room
/// holds and not bans, and to be the file that was listed: its name and size.
#[allow(clippy::too_many_arguments)]
pub(super) async fn accept_pulled_offer(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &crate::host::AppHandle,
    channel_id: [u8; 16],
    offer: ember::channel::XferOffer,
    key: [u8; 32],
    sealed: bool,
    pull: Pull,
) {
    let xfer_id = offer.xfer_id;
    let me = state.local_ed25519_pubkey;
    // A banned member is not answered, as their offers never are. One the
    // room no longer shows is told no, so its send does not wait out the
    // offer's time for an answer that is not coming.
    if channel_member_banned(state, db, channel_id, &offer.sender) {
        emit_pull(app_handle, &xfer_id, &pull, "not_allowed");
        return;
    }
    if !channel_member_on_roster(state, db, channel_id, &offer.sender) {
        let reply = ember::channel::encode_xfer_reply(&key, &me, &offer.sender, &xfer_id, ember::channel::XferReply::Decline);
        send_xfer_frame(socket, state, db, channel_id, offer.sender, &reply).await;
        emit_pull(app_handle, &xfer_id, &pull, "not_allowed");
        return;
    }
    if sealed {
        let seen = ember::channel::encode_xfer_seen(&key, &me, &offer.sender, &xfer_id);
        send_xfer_frame(socket, state, db, channel_id, offer.sender, &seen).await;
    }
    let name = crate::security::sanitize_filename(&offer.name);
    let taken = state.xfer_pending.contains_key(&xfer_id)
        || state.xfer_recv.contains_key(&xfer_id)
        || state.xfer_send.contains_key(&xfer_id)
        || state.xfer_finishing.contains_key(&xfer_id);
    if name != pull.name || offer.size != pull.size || taken {
        let reply = ember::channel::encode_xfer_reply(&key, &me, &offer.sender, &xfer_id, ember::channel::XferReply::Decline);
        send_xfer_frame(socket, state, db, channel_id, offer.sender, &reply).await;
        emit_pull(app_handle, &xfer_id, &pull, "unavailable");
        return;
    }
    let pending = |name: String| ember::xfer::PendingOffer {
        channel_id,
        peer: offer.sender,
        key,
        name,
        size: offer.size,
        root: offer.root,
        received_at: Instant::now(),
    };
    state.xfer_pending.insert(xfer_id, pending(name.clone()));
    let (tx, rx) = oneshot::channel();
    begin_xfer_accept(state, db, app_handle, xfer_id, pending(name), pull.download_folder, tx);
    let work = state.room_library.work_tx.clone();
    tokio::spawn(async move {
        if let Ok(Err(error)) = rx.await {
            let _ = work.send(LibraryWork::AcceptFailed { xfer_id, error });
        }
    });
}

/// One pass: what was readied off the loop, fetches whose turn has come,
/// waits that have run out, and, once a second, lapsed announcements and
/// open libraries due to be announced again.
pub(super) async fn drive_room_libraries(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &crate::host::AppHandle,
) {
    while let Ok(work) = state.room_library.work_rx.try_recv() {
        apply_work(socket, state, db, app_handle, work).await;
    }
    let now = Instant::now();

    // Browses nobody answered: dropping the sender tells the command.
    state
        .room_library
        .asks
        .retain(|_, ask| now.saturating_duration_since(ask.sent_at) < ASK_WAIT);
    for (xfer_id, pull) in state.room_library.lapse(now) {
        emit_pull(app_handle, &xfer_id, &pull, "unavailable");
    }
    let sending = &state.xfer_send;
    state.room_library.serving.retain(|xfer_id, _| sending.contains_key(xfer_id));

    // Fetches whose turn has come, oldest first, while receives are free.
    let held = state.xfer_recv.len() + state.xfer_accepting.len() + state.room_library.held_receives();
    let free = ember::channel::XFER_MAX_ACTIVE.saturating_sub(held);
    for xfer_id in state.room_library.due(free, now) {
        let Some((channel_id, peer, request)) = state
            .room_library
            .pulls
            .get(&xfer_id)
            .map(|pull| (pull.channel_id, pull.peer, LibraryRequest::Fetch { file: pull.file, size: pull.size }))
        else {
            continue;
        };
        let sent = send_request(socket, state, db, channel_id, peer, xfer_id, &request).await;
        if let Some(pull) = state.room_library.asked(&xfer_id, sent, now) {
            emit_pull(app_handle, &xfer_id, &pull, "requested");
        }
    }

    if state
        .room_library
        .upkeep_at
        .is_some_and(|at| now.saturating_duration_since(at) < UPKEEP_EVERY)
    {
        return;
    }
    state.room_library.upkeep_at = Some(now);
    for (channel_id, member) in state.room_library.lapse_heard(now) {
        emit_heard(app_handle, &channel_id, &member, false);
    }
    let library = &mut state.room_library;
    for rates in [&mut library.list_rates, &mut library.fetch_rates] {
        ember::channel::prune_rate_windows(rates, now, FETCH_RATE.0.max(LIST_RATE.0));
    }
    let open = crate::sharing::room_library::open_rooms();
    state.room_library.announced.retain(|room, _| open.contains(room));
    for channel_id in open {
        if state.room_library.announce_due(channel_id, now) {
            let sent = announce(socket, state, db, channel_id, true).await;
            state.room_library.note_announced(channel_id, sent, now);
        }
    }
}

async fn apply_work(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &crate::host::AppHandle,
    work: LibraryWork,
) {
    match work {
        LibraryWork::Answer { channel_id, peer, request_id, answer } => {
            // Asked again now the page is ready, as a fetch is: a walk can
            // take a while, and a member banned or a library closed in the
            // meantime is not sent the page.
            let room = cached_channel_view(state, db, channel_id).map(|view| view.row);
            let allowed = room.is_some_and(|row| room_allows_library(state, db, &row, channel_id))
                && channel_member_on_roster(state, db, channel_id, &peer);
            if !allowed {
                return;
            }
            let answer = if crate::sharing::room_library::is_open(&channel_id) {
                answer
            } else {
                LibraryAnswer::Closed
            };
            send_answer(socket, state, db, channel_id, peer, request_id, &answer).await;
        }
        LibraryWork::Refuse { channel_id, peer, xfer_id, reason } => {
            state.room_library.preparing.remove(&xfer_id);
            let room = cached_channel_view(state, db, channel_id).map(|view| view.row);
            if room.is_some_and(|row| room_allows_library(state, db, &row, channel_id))
                && channel_member_on_roster(state, db, channel_id, &peer)
            {
                send_answer(socket, state, db, channel_id, peer, xfer_id, &LibraryAnswer::Refused(reason)).await;
            }
        }
        LibraryWork::Offer { offer } => {
            let (channel_id, peer, xfer_id) = (offer.channel_id, offer.peer, offer.xfer_id);
            state.room_library.preparing.remove(&xfer_id);
            // Asked again now the file is ready: the library may have closed,
            // the member been banned, or we left, while it was hashed.
            let room = cached_channel_view(state, db, channel_id).map(|view| view.row);
            let still = crate::sharing::room_library::is_open(&channel_id)
                && room.is_some_and(|row| room_allows_library(state, db, &row, channel_id))
                && channel_member_on_roster(state, db, channel_id, &peer);
            if !still {
                let gone = LibraryAnswer::Refused(FetchRefusal::Gone);
                send_answer(socket, state, db, channel_id, peer, xfer_id, &gone).await;
                return;
            }
            let path = offer.path.clone();
            let (tx, _rx) = oneshot::channel();
            match start_xfer_offer(socket, state, db, app_handle, offer, tx).await {
                Ok(()) => {
                    state.room_library.serving.insert(xfer_id, (channel_id, path));
                }
                Err(error) => {
                    let reason = if error.contains("channels_xfer_busy") {
                        FetchRefusal::Busy
                    } else {
                        FetchRefusal::Failed
                    };
                    send_answer(socket, state, db, channel_id, peer, xfer_id, &LibraryAnswer::Refused(reason)).await;
                }
            }
        }
        LibraryWork::AcceptFailed { xfer_id, error } => {
            // An accept that failed leaves its offer waiting, as a prompt the
            // user could still answer; a fetch has no prompt, so it is turned
            // down and the user told why.
            let Some(offer) = state.xfer_pending.get(&xfer_id) else {
                return;
            };
            let channel_id = offer.channel_id;
            let offer = ember::xfer::PendingOffer {
                channel_id,
                peer: offer.peer,
                key: offer.key,
                name: offer.name.clone(),
                size: offer.size,
                root: offer.root,
                received_at: offer.received_at,
            };
            let (tx, _rx) = oneshot::channel();
            answer_xfer_offer(socket, state, db, app_handle, xfer_id, offer, false, tx).await;
            let _ = app_handle.emit(
                "ember:room-library-error",
                serde_json::json!({
                    "xfer_id": hex::encode(xfer_id),
                    "channel_id": hex::encode(channel_id),
                    "error": error,
                }),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: [u8; 16] = [1; 16];
    const OTHER_ROOM: [u8; 16] = [2; 16];
    const OWNER: [u8; 32] = [3; 32];
    const STRANGER: [u8; 32] = [4; 32];

    fn request(file: u8) -> PullRequest {
        PullRequest {
            channel_id: ROOM,
            peer: OWNER,
            file: [file; 8],
            name: format!("file {file}.flac"),
            size: 1_000,
            download_folder: std::path::PathBuf::from("downloads"),
        }
    }

    fn id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    fn queued(library: &mut LibraryState, file: u8, now: Instant) -> [u8; 16] {
        library.queue(request(file), id(file), now).unwrap().0
    }

    #[test]
    fn a_fetch_is_asked_for_in_turn_and_its_offer_claims_it_once() {
        let mut library = LibraryState::new();
        let now = Instant::now();
        let first = queued(&mut library, 1, now);
        let second = queued(&mut library, 2, now + Duration::from_millis(1));
        // Oldest first, and no more than the receives free.
        assert_eq!(library.due(1, now), vec![first]);
        assert!(library.asked(&first, true, now).is_some());
        assert_eq!(library.held_receives(), 1);
        assert_eq!(library.due(4, now), vec![second], "an asked-for fetch is not asked again");
        // An offer from someone else, or in another room, is not ours.
        assert!(matches!(library.claim(ROOM, STRANGER, first), OfferClaim::None));
        assert!(matches!(library.claim(OTHER_ROOM, OWNER, first), OfferClaim::None));
        // The owner readies it, then offers it.
        assert!(library.on_fetch_answer(ROOM, OWNER, first, &LibraryAnswer::Preparing, now).is_none());
        let OfferClaim::Pull(pull) = library.claim(ROOM, OWNER, first) else {
            panic!("the offer of a fetch asked for is ours");
        };
        assert_eq!(pull.name, "file 1.flac");
        assert!(matches!(library.claim(ROOM, OWNER, first), OfferClaim::None), "claimed once");
    }

    #[test]
    fn a_queued_fetch_is_not_claimed_by_an_offer_it_never_asked_for() {
        let mut library = LibraryState::new();
        let now = Instant::now();
        let waiting = queued(&mut library, 1, now);
        assert!(matches!(library.claim(ROOM, OWNER, waiting), OfferClaim::None));
        assert_eq!(library.pulls.len(), 1, "still waiting its turn");
    }

    #[test]
    fn the_same_file_is_queued_once_and_the_queue_has_a_cap() {
        let mut library = LibraryState::new();
        let now = Instant::now();
        let first = queued(&mut library, 1, now);
        assert_eq!(library.queue(request(1), id(99), now).unwrap(), (first, false));
        for n in 2..=PULLS_MAX as u8 {
            library.queue(request(n), id(n), now).unwrap();
        }
        assert_eq!(library.pulls.len(), PULLS_MAX);
        let mut extra = request(1);
        extra.file = [0xFF; 8];
        assert!(library.queue(extra, id(0xFF), now).is_err());
    }

    #[test]
    fn a_fetch_a_room_transfer_cannot_carry_is_refused() {
        let mut library = LibraryState::new();
        let now = Instant::now();
        let mut huge = request(2);
        huge.size = ember::channel::XFER_MAX_BYTES + 1;
        assert!(library.queue(huge, id(2), now).is_err());
        let mut empty = request(3);
        empty.size = 0;
        assert!(library.queue(empty, id(3), now).is_err());
    }

    #[test]
    fn a_busy_owner_puts_the_fetch_back_until_it_has_been_tried_enough() {
        let mut library = LibraryState::new();
        let mut now = Instant::now();
        let fetch = queued(&mut library, 1, now);
        for _ in 0..FETCH_TRIES {
            assert_eq!(library.due(4, now), vec![fetch]);
            library.asked(&fetch, true, now);
            let (_, status) = library
                .on_fetch_answer(ROOM, OWNER, fetch, &LibraryAnswer::Refused(FetchRefusal::Busy), now)
                .unwrap();
            assert_eq!(status, "queued");
            assert!(library.due(4, now).is_empty(), "waits before it is asked again");
            now += FETCH_RETRY_AFTER;
        }
        let lapsed = library.lapse(now);
        assert_eq!(lapsed.len(), 1, "given up after {FETCH_TRIES} tries");
        assert!(library.pulls.is_empty());
    }

    #[test]
    fn an_owner_that_says_gone_or_closed_ends_the_fetch() {
        let mut library = LibraryState::new();
        let now = Instant::now();
        for (n, answer) in [
            (1, LibraryAnswer::Refused(FetchRefusal::Gone)),
            (2, LibraryAnswer::Refused(FetchRefusal::Failed)),
            (3, LibraryAnswer::Closed),
            (4, LibraryAnswer::Missing),
        ] {
            let fetch = queued(&mut library, n, now);
            library.asked(&fetch, true, now);
            let (_, status) = library.on_fetch_answer(ROOM, OWNER, fetch, &answer, now).unwrap();
            assert_eq!(status, "unavailable");
            // An offer it was already readying is turned down, not prompted for.
            assert!(matches!(library.claim(ROOM, OWNER, fetch), OfferClaim::Cancelled));
        }
    }

    #[test]
    fn an_answer_from_anyone_but_the_owner_asked_is_ignored() {
        let mut library = LibraryState::new();
        let now = Instant::now();
        let fetch = queued(&mut library, 1, now);
        library.asked(&fetch, true, now);
        let gone = LibraryAnswer::Refused(FetchRefusal::Gone);
        assert!(library.on_fetch_answer(ROOM, STRANGER, fetch, &gone, now).is_none());
        assert!(library.on_fetch_answer(OTHER_ROOM, OWNER, fetch, &gone, now).is_none());
        assert_eq!(library.pulls.len(), 1);
    }

    #[test]
    fn unanswered_fetches_lapse_and_a_late_offer_is_turned_down() {
        let mut library = LibraryState::new();
        let now = Instant::now();
        let silent = queued(&mut library, 1, now);
        let readying = queued(&mut library, 2, now);
        library.asked(&silent, true, now);
        library.asked(&readying, true, now);
        library.on_fetch_answer(ROOM, OWNER, readying, &LibraryAnswer::Preparing, now);
        let later = now + FETCH_ANSWER_WAIT + Duration::from_secs(1);
        let lapsed: Vec<[u8; 16]> = library.lapse(later).into_iter().map(|(id, _)| id).collect();
        assert_eq!(lapsed, vec![silent], "a file being readied has longer");
        assert!(matches!(library.claim(ROOM, OWNER, silent), OfferClaim::Cancelled));
        let much_later = now + FETCH_PREPARE_WAIT + Duration::from_secs(1);
        assert_eq!(library.lapse(much_later).len(), 1);
        // And the memory of a given-up fetch does not last for ever.
        let gone = queued(&mut library, 3, now);
        library.asked(&gone, true, now);
        library.give_up(&gone, now);
        library.lapse(now + CANCELLED_FOR + Duration::from_secs(1));
        assert!(matches!(library.claim(ROOM, OWNER, gone), OfferClaim::None));
    }

    #[test]
    fn a_fetch_given_up_before_it_was_asked_leaves_nothing_to_turn_down() {
        let mut library = LibraryState::new();
        let now = Instant::now();
        let fetch = queued(&mut library, 1, now);
        assert!(library.give_up(&fetch, now).is_some());
        assert!(matches!(library.claim(ROOM, OWNER, fetch), OfferClaim::None));
    }

    #[test]
    fn leaving_a_room_or_a_ban_gives_up_its_fetches() {
        let mut library = LibraryState::new();
        let now = Instant::now();
        queued(&mut library, 1, now);
        let mut elsewhere = request(2);
        elsewhere.channel_id = OTHER_ROOM;
        library.queue(elsewhere, id(2), now).unwrap();
        let mut from_stranger = request(3);
        from_stranger.peer = STRANGER;
        library.queue(from_stranger, id(3), now).unwrap();
        assert_eq!(library.give_up_in(ROOM, Some(STRANGER), now).len(), 1);
        assert_eq!(library.give_up_in(ROOM, None, now).len(), 1);
        assert_eq!(library.pulls.len(), 1, "another room's stay");
    }

    #[test]
    fn a_failed_send_waits_and_counts_as_a_try() {
        let mut library = LibraryState::new();
        let now = Instant::now();
        let fetch = queued(&mut library, 1, now);
        assert!(library.asked(&fetch, false, now).is_none());
        assert_eq!(library.held_receives(), 0);
        assert!(library.due(4, now).is_empty());
        assert_eq!(library.due(4, now + FETCH_RETRY_AFTER), vec![fetch]);
        assert!(matches!(library.pulls[&fetch].stage, PullStage::Queued { tries: 1, .. }));
    }

    #[test]
    fn an_open_library_is_announced_often_at_first_then_every_few_minutes() {
        let mut library = LibraryState::new();
        let now = Instant::now();
        assert!(library.announce_due(ROOM, now));
        library.note_announced(ROOM, false, now);
        assert!(!library.announce_due(ROOM, now + Duration::from_secs(1)), "a failed try is not repeated at once");
        let mut at = now;
        for _ in 0..ANNOUNCE_EARLY {
            at += ANNOUNCE_EARLY_EVERY;
            assert!(library.announce_due(ROOM, at));
            library.note_announced(ROOM, true, at);
        }
        assert!(!library.announce_due(ROOM, at + ANNOUNCE_EARLY_EVERY));
        assert!(library.announce_due(ROOM, at + ANNOUNCE_EVERY));
        assert!(library.announce_due(OTHER_ROOM, now), "each room on its own");
    }

    #[test]
    fn what_a_member_last_said_of_their_library_stands_until_it_lapses() {
        let mut library = LibraryState::new();
        let now = Instant::now();
        assert!(library.hear(ROOM, OWNER, true, 100, now), "opened");
        assert!(!library.hear(ROOM, OWNER, true, 200, now), "said again");
        assert!(!library.hear(ROOM, OWNER, false, 150, now), "older than what was heard");
        assert_eq!(library.open_members(ROOM, now), vec![OWNER]);
        assert!(library.open_members(OTHER_ROOM, now).is_empty());
        assert!(library.hear(ROOM, OWNER, false, 300, now), "closed");
        assert!(library.open_members(ROOM, now).is_empty());
        assert!(!library.hear(ROOM, STRANGER, false, 1, now), "closed from the start shows nothing");

        assert!(library.hear(ROOM, OWNER, true, 400, now));
        let later = now + HEARD_FOR;
        assert!(library.open_members(ROOM, later).is_empty());
        assert_eq!(library.lapse_heard(later), vec![(ROOM, OWNER)]);
        assert!(!library.heard.contains_key(&(ROOM, STRANGER)), "a lapsed closed word is forgotten too");
        assert!(library.hear(ROOM, OWNER, true, 500, later), "opened again");
    }
}
