//! Friend browse-request queueing and dispatch.
//!
//! What belongs here: the per-friend FIFO of outstanding browse requests and
//! everything that manipulates it — enqueue, complete, cancel, session
//! rebinding, and the dispatcher that puts the queue head on the wire.
//!
//! What does not belong here: Ember session lifecycle (`retire_ember_session`
//! and friends live in the parent module because friend removal and transfer
//! paths retire sessions for reasons unrelated to browsing), and the command
//! handlers that decide *when* to browse.

use std::collections::{HashMap, HashSet, VecDeque};

use tauri::Emitter;

use super::ed2k;
use super::ed2k::messages::OP_EMULEPROT;
use super::{retire_ember_session, NetworkState};

/// A browse request is correlated to the exact authenticated friend TCP
/// session that carried its wire request. The ED2K browse response has no
/// request ID, so a per-friend FIFO alone is unsafe after a reconnect: an old
/// session's delayed response could otherwise be rendered as a new request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingBrowseRequest {
    pub(crate) request_id: String,
    pub(crate) session_id: u64,
    /// True once the wire request has been queued on `session_id`. A later
    /// enqueue must not transmit the current queue head a second time.
    pub(crate) dispatched: bool,
    /// Friends-only hashes the friend announced (`EMBER_EXT_BROWSE_SCOPE`)
    /// ahead of this request's answer. `None` when none arrived, which is
    /// what a peer that predates the scope frame always produces.
    pub(crate) scope: Option<HashSet<[u8; 16]>>,
}

pub(crate) type PendingBrowseRequests = HashMap<[u8; 16], VecDeque<PendingBrowseRequest>>;

/// Outstanding browse requests one friend may have queued at once.
///
/// A browse is one dialog against one friend, so a queue this deep already means
/// something is retrying rather than someone is browsing. The dedup on
/// `request_id` stops the same request being queued twice but says nothing about
/// how many *distinct* ones can pile up, and the dispatcher walks this queue
/// looking for a live head — so an unbounded one costs memory and lengthens
/// every dispatch.
const MAX_PENDING_BROWSE_PER_FRIEND: usize = 8;

pub(crate) fn enqueue_browse_request(
    pending: &mut PendingBrowseRequests,
    friend: [u8; 16],
    request_id: String,
    session_id: u64,
) -> Result<(), ()> {
    let queue = pending.entry(friend).or_default();
    if queue.iter().any(|request| request.request_id == request_id) {
        return Err(());
    }
    if queue.len() >= MAX_PENDING_BROWSE_PER_FRIEND {
        return Err(());
    }
    queue.push_back(PendingBrowseRequest {
        request_id,
        session_id,
        dispatched: false,
        scope: None,
    });
    Ok(())
}

/// Attach a scope frame to the request it precedes: the dispatched head bound
/// to the session that carried it. Anything else is unsolicited and dropped.
pub(crate) fn attach_browse_scope(
    pending: &mut PendingBrowseRequests,
    friend: [u8; 16],
    session_id: u64,
    restricted: Vec<[u8; 16]>,
) -> bool {
    let Some(head) = pending.get_mut(&friend).and_then(|queue| queue.front_mut()) else {
        return false;
    };
    if head.session_id != session_id || !head.dispatched {
        return false;
    }
    head.scope = Some(restricted.into_iter().collect());
    true
}

/// The scope announced for the head request, if the answer came from the
/// session that request is bound to. Read before [`complete_browse_request`].
pub(crate) fn take_browse_scope(
    pending: &mut PendingBrowseRequests,
    friend: [u8; 16],
    session_id: u64,
) -> Option<HashSet<[u8; 16]>> {
    let head = pending.get_mut(&friend)?.front_mut()?;
    if head.session_id != session_id {
        return None;
    }
    head.scope.take()
}

/// Scope body version understood by [`parse_browse_scope`].
const BROWSE_SCOPE_V1: u8 = 0x01;

/// Most hashes one scope frame may carry: a browse answer never lists more.
pub(crate) const MAX_BROWSE_SCOPE_HASHES: usize = 1_000;

/// `EMBER_EXT_BROWSE_SCOPE` body: a version byte, then the 16-byte ED2K hash
/// of every friends-only entry in the answer that follows.
pub(crate) fn encode_browse_scope<'a, I>(restricted: I) -> Vec<u8>
where
    I: IntoIterator<Item = &'a [u8; 16]>,
{
    let mut out = vec![BROWSE_SCOPE_V1];
    for hash in restricted.into_iter().take(MAX_BROWSE_SCOPE_HASHES) {
        out.extend_from_slice(hash);
    }
    out
}

/// `None` for an unknown version, a ragged body, or more hashes than any
/// browse answer can hold.
pub(crate) fn parse_browse_scope(body: &[u8]) -> Option<Vec<[u8; 16]>> {
    let (&version, hashes) = body.split_first()?;
    if version != BROWSE_SCOPE_V1
        || hashes.len() % 16 != 0
        || hashes.len() / 16 > MAX_BROWSE_SCOPE_HASHES
    {
        return None;
    }
    Some(
        hashes
            .chunks_exact(16)
            .map(|chunk| {
                let mut hash = [0u8; 16];
                hash.copy_from_slice(chunk);
                hash
            })
            .collect(),
    )
}

/// Per friend, the hashes that friend last told us are friends-only on their
/// side, learned from browse scopes and file offers.
///
/// Consulted when a download names that friend as its origin, so the copy we
/// build inherits the restriction. Process-wide rather than on
/// `NetworkState` because it is written by the upload-event handler and read
/// by the start-download handler, and holds nothing that must survive a
/// restart: the flag it produces is persisted on the transfer itself.
fn friend_restricted_files() -> &'static std::sync::Mutex<FriendScopes> {
    static REGISTRY: std::sync::OnceLock<std::sync::Mutex<FriendScopes>> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

fn with_friend_scopes<R>(apply: impl FnOnce(&mut FriendScopes) -> R) -> R {
    let mut registry = match friend_restricted_files().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    apply(&mut registry)
}

const MAX_TRACKED_FRIEND_SCOPES: usize = 1_024;
const MAX_RESTRICTED_PER_FRIEND: usize = 8_192;

/// Bounded, and failing closed at the bounds: a restriction that does not fit
/// widens to "everything from this friend" (or, when no more friends fit,
/// "everything from any untracked friend") rather than being dropped, since a
/// dropped entry would let the copy be republished.
#[derive(Default)]
struct FriendScopes {
    friends: HashMap<[u8; 16], FriendScope>,
    overflowed: bool,
}

#[derive(Default)]
struct FriendScope {
    restricted: HashSet<[u8; 16]>,
    overflowed: bool,
}

impl FriendScopes {
    fn record(&mut self, friend: [u8; 16], updates: impl IntoIterator<Item = ([u8; 16], bool)>) {
        for (hash, friends_only) in updates {
            if !friends_only {
                if let Some(scope) = self.friends.get_mut(&friend) {
                    scope.restricted.remove(&hash);
                }
                continue;
            }
            if !self.friends.contains_key(&friend) && self.friends.len() >= MAX_TRACKED_FRIEND_SCOPES
            {
                self.overflowed = true;
                return;
            }
            let scope = self.friends.entry(friend).or_default();
            if scope.restricted.len() >= MAX_RESTRICTED_PER_FRIEND {
                scope.overflowed = true;
            } else {
                scope.restricted.insert(hash);
            }
        }
        if self
            .friends
            .get(&friend)
            .is_some_and(|scope| scope.restricted.is_empty() && !scope.overflowed)
        {
            self.friends.remove(&friend);
        }
    }

    fn marks(&self, friend: [u8; 16], file_hash: &[u8; 16]) -> bool {
        match self.friends.get(&friend) {
            Some(scope) => scope.overflowed || scope.restricted.contains(file_hash),
            None => self.overflowed,
        }
    }

    fn forget(&mut self, friend: [u8; 16]) {
        self.friends.remove(&friend);
    }
}

/// Fold one browse answer into the registry: every listed hash takes the
/// restriction the friend just announced, and unlisted hashes keep theirs.
pub(crate) fn record_friend_listing<'a, I>(
    friend: [u8; 16],
    listed: I,
    restricted: &HashSet<[u8; 16]>,
) where
    I: IntoIterator<Item = &'a [u8; 16]>,
{
    with_friend_scopes(|scopes| {
        scopes.record(
            friend,
            listed.into_iter().map(|hash| (*hash, restricted.contains(hash))),
        )
    });
}

pub(crate) fn record_friend_offer(friend: [u8; 16], file_hash: [u8; 16], friends_only: bool) {
    with_friend_scopes(|scopes| scopes.record(friend, [(file_hash, friends_only)]));
}

/// Whether `friend` told us `file_hash` is friends-only on their side.
pub(crate) fn friend_marked_friends_only(friend: [u8; 16], file_hash: &[u8; 16]) -> bool {
    with_friend_scopes(|scopes| scopes.marks(friend, file_hash))
}

/// Drop what a removed or blocked friend told us. The global overflow flag is
/// deliberately left set: it stands for restrictions already lost.
pub(crate) fn forget_friend_scope(friend: [u8; 16]) {
    with_friend_scopes(|scopes| scopes.forget(friend));
}

/// Take the queue head only when the response came from the same session that
/// sent it. The caller must always run [`dispatch_browse_head`] afterward:
/// the next head may belong to a newer session.
pub(crate) fn complete_browse_request(
    pending: &mut PendingBrowseRequests,
    friend: [u8; 16],
    session_id: u64,
) -> Option<String> {
    let queue = pending.get_mut(&friend)?;
    if queue
        .front()
        .is_none_or(|request| request.session_id != session_id)
    {
        return None;
    }
    let request_id = queue.pop_front()?.request_id;
    if queue.is_empty() {
        pending.remove(&friend);
    }
    Some(request_id)
}

pub(crate) fn remove_browse_requests_for_session(
    pending: &mut PendingBrowseRequests,
    friend: [u8; 16],
    session_id: u64,
) -> Vec<String> {
    let Some(queue) = pending.get_mut(&friend) else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    queue.retain(|request| {
        if request.session_id == session_id {
            removed.push(request.request_id.clone());
            false
        } else {
            true
        }
    });
    if queue.is_empty() {
        pending.remove(&friend);
    }
    removed
}

/// Cancel a request. Cancelling the active head invalidates every request
/// bound to that session: a late reply cannot be distinguished on the wire,
/// so the caller must retire the session before starting another browse.
pub(crate) fn cancel_browse_request(
    pending: &mut PendingBrowseRequests,
    friend: [u8; 16],
    request_id: &str,
) -> Option<(Option<u64>, Vec<String>)> {
    let queue = pending.get_mut(&friend)?;
    let position = queue
        .iter()
        .position(|request| request.request_id == request_id)?;
    if position != 0 {
        queue.remove(position);
        return Some((None, Vec::new()));
    }

    let session_id = queue.front()?.session_id;
    let mut invalidated = Vec::new();
    queue.retain(|request| {
        if request.session_id == session_id {
            if request.request_id != request_id {
                invalidated.push(request.request_id.clone());
            }
            false
        } else {
            true
        }
    });
    if queue.is_empty() {
        pending.remove(&friend);
    }
    Some((Some(session_id), invalidated))
}

/// Bind an on-demand browse placeholder (session ID 0) to the freshly opened
/// session before its first wire packet is queued.
pub(crate) fn bind_browse_request_to_session(
    pending: &mut PendingBrowseRequests,
    friend: [u8; 16],
    request_id: &str,
    session_id: u64,
) -> Option<()> {
    let queue = pending.get_mut(&friend)?;
    let position = queue
        .iter()
        .position(|request| request.request_id == request_id)?;
    let request = queue.get_mut(position)?;
    if request.session_id != 0 {
        return None;
    }
    request.session_id = session_id;
    Some(())
}

pub(crate) fn remove_browse_request(
    pending: &mut PendingBrowseRequests,
    friend: [u8; 16],
    request_id: &str,
) -> Option<PendingBrowseRequest> {
    let queue = pending.get_mut(&friend)?;
    let position = queue
        .iter()
        .position(|request| request.request_id == request_id)?;
    let removed = queue.remove(position)?;
    if queue.is_empty() {
        pending.remove(&friend);
    }
    Some(removed)
}

pub(crate) fn browse_request_is_pending(
    pending: &PendingBrowseRequests,
    friend: [u8; 16],
    request_id: &str,
) -> bool {
    pending
        .get(&friend)
        .is_some_and(|queue| queue.iter().any(|request| request.request_id == request_id))
}

pub(crate) fn send_browse_response_to_origin(
    reply_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    packet: Vec<u8>,
) -> Result<(), tokio::sync::mpsc::error::TrySendError<Vec<u8>>> {
    reply_tx.try_send(packet)
}

pub(crate) async fn dispatch_browse_head(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    friend: [u8; 16],
) {
    loop {
        let Some(head) = state
            .pending_browse_requests
            .get(&friend)
            .and_then(|queue| queue.front())
            .cloned()
        else {
            return;
        };
        // Session ID 0 is a placeholder while an on-demand dial is in
        // progress. Its `EmberBrowseSessionReady` event will re-enter this
        // dispatcher after binding the real session ID.
        if head.session_id == 0 || head.dispatched {
            return;
        }

        let current = state.ember_sessions.read().await.get(&friend).cloned();
        let reason = match current {
            Some(handle) if handle.session_id() == head.session_id && handle.is_fresh() => {
                let mut packet = Vec::with_capacity(10);
                packet.push(OP_EMULEPROT);
                packet.extend_from_slice(&(5u32).to_le_bytes());
                packet.push(ed2k::messages::OP_EMBER_BROWSE_REQ);
                packet.extend_from_slice(ed2k::multi_source::BROWSE_RESPONSE_V1_MAGIC);
                match handle.tx.try_send(packet) {
                    Ok(()) => {
                        if let Some(request) = state
                            .pending_browse_requests
                            .get_mut(&friend)
                            .and_then(|queue| queue.front_mut())
                            .filter(|request| {
                                request.request_id == head.request_id
                                    && request.session_id == head.session_id
                            })
                        {
                            request.dispatched = true;
                        }
                        return;
                    }
                    Err(error) => {
                        let _ =
                            retire_ember_session(&state.ember_sessions, friend, head.session_id)
                                .await;
                        format!("Browse request could not be queued: {error}")
                    }
                }
            }
            Some(_) => "Browse session was replaced before the request was sent".into(),
            None => "Friend disconnected before the browse request was sent".into(),
        };

        // A stale head must never block a request already associated with the
        // current replacement session. Drop it and immediately inspect the
        // new head in the next loop iteration.
        let _ = remove_browse_request(&mut state.pending_browse_requests, friend, &head.request_id);
        let _ = app_handle.emit(
            "ember:browse-error",
            serde_json::json!({
                "user_hash": hex::encode(friend),
                "request_id": head.request_id,
                "reason": reason,
            }),
        );
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    fn dispatched_head(pending: &mut PendingBrowseRequests, friend: [u8; 16], session_id: u64) {
        enqueue_browse_request(pending, friend, "req".into(), session_id).unwrap();
        pending.get_mut(&friend).unwrap().front_mut().unwrap().dispatched = true;
    }

    #[test]
    fn browse_scope_round_trips_with_and_without_hashes() {
        let hashes = [[0x11u8; 16], [0x22u8; 16]];
        let body = encode_browse_scope(hashes.iter());
        assert_eq!(body.len(), 1 + 32);
        assert_eq!(parse_browse_scope(&body), Some(hashes.to_vec()));

        let empty = encode_browse_scope(std::iter::empty());
        assert_eq!(parse_browse_scope(&empty), Some(Vec::new()));
    }

    #[test]
    fn browse_scope_rejects_malformed_bodies() {
        assert_eq!(parse_browse_scope(&[]), None);
        let mut ragged = encode_browse_scope([[0x33u8; 16]].iter());
        ragged.push(0);
        assert_eq!(parse_browse_scope(&ragged), None);
        let mut future = encode_browse_scope([[0x33u8; 16]].iter());
        future[0] = 0x02;
        assert_eq!(parse_browse_scope(&future), None);
        let mut oversized = vec![BROWSE_SCOPE_V1];
        oversized.resize(1 + (MAX_BROWSE_SCOPE_HASHES + 1) * 16, 0xAA);
        assert_eq!(parse_browse_scope(&oversized), None);
    }

    #[test]
    fn browse_scope_attaches_only_to_the_dispatched_head_of_its_session() {
        let friend = [0x40u8; 16];
        let mut pending = PendingBrowseRequests::new();
        enqueue_browse_request(&mut pending, friend, "req".into(), 7).unwrap();
        assert!(!attach_browse_scope(&mut pending, friend, 7, vec![[1u8; 16]]));

        pending.get_mut(&friend).unwrap().front_mut().unwrap().dispatched = true;
        assert!(!attach_browse_scope(&mut pending, friend, 8, vec![[1u8; 16]]));
        assert!(attach_browse_scope(&mut pending, friend, 7, vec![[1u8; 16]]));

        assert_eq!(take_browse_scope(&mut pending, friend, 8), None);
        let scope = take_browse_scope(&mut pending, friend, 7).unwrap();
        assert!(scope.contains(&[1u8; 16]));
        assert_eq!(take_browse_scope(&mut pending, friend, 7), None);
    }

    #[test]
    fn answer_without_a_scope_frame_reads_as_unrestricted() {
        let friend = [0x41u8; 16];
        let mut pending = PendingBrowseRequests::new();
        dispatched_head(&mut pending, friend, 3);
        assert_eq!(take_browse_scope(&mut pending, friend, 3), None);
    }

    #[test]
    fn friend_listing_marks_and_clears_restrictions() {
        let friend = [0x42u8; 16];
        let private = [0xA1u8; 16];
        let public = [0xA2u8; 16];
        let restricted: HashSet<[u8; 16]> = [private].into_iter().collect();
        record_friend_listing(friend, [private, public].iter(), &restricted);
        assert!(friend_marked_friends_only(friend, &private));
        assert!(!friend_marked_friends_only(friend, &public));
        assert!(!friend_marked_friends_only([0x43u8; 16], &private));

        // Relisted without the scope (an older build, or the owner made it
        // public): the restriction is lifted.
        record_friend_listing(friend, [private].iter(), &HashSet::new());
        assert!(!friend_marked_friends_only(friend, &private));
    }

    #[test]
    fn a_full_friend_scope_restricts_everything_from_that_friend() {
        let friend = [0x50u8; 16];
        let other = [0x51u8; 16];
        let mut scopes = FriendScopes::default();
        scopes.record(
            friend,
            (0..MAX_RESTRICTED_PER_FRIEND as u32).map(|i| {
                let mut hash = [0u8; 16];
                hash[..4].copy_from_slice(&i.to_le_bytes());
                (hash, true)
            }),
        );
        let never_listed = [0xFFu8; 16];
        assert!(!scopes.marks(friend, &never_listed));

        scopes.record(friend, [([0xFEu8; 16], true)]);
        assert!(scopes.marks(friend, &never_listed), "overflow fails closed");
        assert!(!scopes.marks(other, &never_listed), "other friends are unaffected");

        scopes.forget(friend);
        assert!(!scopes.marks(friend, &never_listed));
    }

    #[test]
    fn a_full_registry_restricts_every_untracked_friend() {
        let mut scopes = FriendScopes::default();
        for i in 0..MAX_TRACKED_FRIEND_SCOPES as u32 {
            let mut friend = [0u8; 16];
            friend[..4].copy_from_slice(&i.to_le_bytes());
            scopes.record(friend, [([0xA0u8; 16], true)]);
        }
        let tracked = [0u8; 16];
        let untracked = [0xEEu8; 16];
        assert!(!scopes.marks(untracked, &[0xA1u8; 16]));
        assert!(!scopes.marks(tracked, &[0xA1u8; 16]));

        // An unrestricted-only update needs no slot and changes nothing.
        scopes.record(untracked, [([0xA1u8; 16], false)]);
        assert!(!scopes.marks(untracked, &[0xA1u8; 16]));

        scopes.record(untracked, [([0xA1u8; 16], true)]);
        assert!(scopes.marks(untracked, &[0xA2u8; 16]), "lost restriction fails closed");
        assert!(!scopes.marks(tracked, &[0xA1u8; 16]), "tracked friends keep exact answers");
        assert!(scopes.marks(tracked, &[0xA0u8; 16]));

        scopes.forget(tracked);
        assert!(scopes.marks(tracked, &[0xA1u8; 16]), "overflow outlives a forget");
    }

    #[test]
    fn forgetting_a_friend_drops_their_restrictions() {
        let friend = [0x52u8; 16];
        let file = [0xC1u8; 16];
        record_friend_offer(friend, file, true);
        assert!(friend_marked_friends_only(friend, &file));
        forget_friend_scope(friend);
        assert!(!friend_marked_friends_only(friend, &file));
    }

    #[test]
    fn friend_offer_marks_and_clears_restrictions() {
        let friend = [0x44u8; 16];
        let file = [0xB1u8; 16];
        record_friend_offer(friend, file, true);
        assert!(friend_marked_friends_only(friend, &file));
        record_friend_offer(friend, file, false);
        assert!(!friend_marked_friends_only(friend, &file));
    }
}
