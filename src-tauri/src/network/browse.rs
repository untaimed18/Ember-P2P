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

use std::collections::{HashMap, VecDeque};

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
}

pub(crate) type PendingBrowseRequests = HashMap<[u8; 16], VecDeque<PendingBrowseRequest>>;

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
    queue.push_back(PendingBrowseRequest {
        request_id,
        session_id,
        dispatched: false,
    });
    Ok(())
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
