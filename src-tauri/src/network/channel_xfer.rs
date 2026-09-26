//! Ember Transfer: file offers, block exchange, and completion for channel
//! and friend transfers.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Data-block budget, deliberately separate from the chat one.
///
/// The withdrawn attachment path spent `CHANNEL_GOSSIP_OUT_PER_SEC` on file
/// chunks, which had two consequences: a transfer silenced the room's chat
/// while it ran, and it abandoned itself the moment the shared allowance ran
/// out — a few kilobytes in, with no way to resume. Blocks get their own
/// allowance; the small control frames keep using the chat one, where they
/// belong.
pub(super) fn xfer_block_rate_ok(state: &mut NetworkState) -> bool {
    ember::channel::rate_window_allow(
        &mut state.xfer_block_times,
        std::time::Instant::now(),
        CHANNEL_GOSSIP_RATE_WINDOW,
        ember::channel::XFER_BLOCKS_OUT_PER_SEC,
    )
}

/// Whether the user's upload cap has `bytes` to spare for a transfer block.
///
/// Takes what the limiter will give without waiting and banks it, spending only
/// once a whole block is covered. Under an unlimited cap the limiter grants
/// everything, so this is a straight pass-through; under a cap smaller than one
/// block it fills up over several ticks instead of never being satisfiable.
pub(super) fn xfer_upload_allowance_ok(
    state: &mut NetworkState,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    bytes: u64,
) -> bool {
    if state.xfer_upload_credit < bytes {
        let wanted = bytes - state.xfer_upload_credit;
        state.xfer_upload_credit += bandwidth_limiter.try_take_upload(wanted);
    }
    if state.xfer_upload_credit < bytes {
        return false;
    }
    state.xfer_upload_credit -= bytes;
    true
}

/// Seal one transfer frame and send it to a single member.
///
/// Direct Noise session first, then the channel WebSocket relay, then the
/// overlay — the same ladder chat uses, so two firewalled members can still
/// move a file. Never fans out: a transfer is nobody's business but the two
/// ends', and broadcasting it is exactly what made the old path unusable.
pub(super) async fn send_xfer_frame(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    channel_id: [u8; 16],
    peer: [u8; 32],
    plain: &[u8],
) -> bool {
    let Some(view) = cached_channel_view(state, db, channel_id) else {
        return false;
    };
    // `content_keys` is newest-epoch-first, so the head is what
    // `channel_content_key` would have returned.
    let Some(key) = view.content_keys.into_iter().next() else {
        return false;
    };
    // TTL 1: addressed, so no one should ever relay it onward as gossip.
    let gossip = ember::channel::ChannelGossip::new_plaintext(
        channel_id,
        &key,
        chrono::Utc::now().timestamp().max(0) as u64,
        plain,
        1,
    );
    let body = gossip.encode();
    // Remember our own id: a relay can loop the frame back, and the dedup set
    // is what stops us reading our own block as an inbound one.
    let _ = remember_channel_gossip(state, gossip.msg_id);
    let node_id = ember::dht::EmberNodeId(ember::channel::channel_id_from_pubkey(&peer));
    if let Some(contact) = state.ember_dht.routing().get_contact(&node_id).cloned() {
        if ember_has_live_session(state, &contact) {
            let (_rid, frame) = state.ember_dht.build_channel_msg(body.clone());
            if send_ember_dht_frame_established(socket, state, &contact, &frame).await {
                return true;
            }
        }
    }
    if let Some((_, tx)) = state.channel_relay_outboxes.get(&peer) {
        if tx.try_send(body.clone()).is_ok() {
            return true;
        }
    }
    let roster = channel_member_pubkeys_cached(state, db, channel_id);
    overlay_forward_channel_gossip(socket, state, &channel_id, &body, &[peer], &roster).await
}

/// Drop the transfers tied to one room, optionally only those with one member.
///
/// A ban has to reach the transfer engine, not just the roster. Without this an
/// accepted download kept pulling blocks from somebody the room had just
/// evicted, a pending offer of theirs stayed answerable, and an upload of ours
/// kept feeding them — none of it stopping until the stall shed noticed ninety
/// seconds later, and not even then while blocks were still arriving.
///
/// `member` of `None` means every transfer in the room, which is what leaving it
/// wants.
pub(super) fn drop_channel_transfers_for(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    channel_id: [u8; 16],
    member: Option<[u8; 32]>,
    status: &str,
) {
    let matches = |room: &[u8; 16], peer: &[u8; 32]| {
        *room == channel_id && member.is_none_or(|wanted| wanted == *peer)
    };
    let mut ended: Vec<([u8; 16], [u8; 32], String, u64, &'static str)> = Vec::new();
    state.xfer_pending.retain(|xfer_id, offer| {
        if matches(&offer.channel_id, &offer.peer) {
            ended.push((*xfer_id, offer.peer, offer.name.clone(), offer.size, "receive"));
            return false;
        }
        true
    });
    state.xfer_recv.retain(|xfer_id, recv| {
        if matches(&recv.channel_id, &recv.peer) {
            // Half a file is not a file.
            let _ = std::fs::remove_file(&recv.part_path);
            ended.push((*xfer_id, recv.peer, recv.name.clone(), recv.size, "receive"));
            return false;
        }
        true
    });
    state.xfer_send.retain(|xfer_id, send| {
        if matches(&send.channel_id, &send.peer) {
            ended.push((*xfer_id, send.peer, send.name.clone(), send.size, "send"));
            return false;
        }
        true
    });
    for (xfer_id, peer, name, size, direction) in ended {
        emit_xfer_update(
            app_handle,
            &xfer_id,
            &channel_id,
            &peer,
            direction,
            &name,
            size,
            0,
            status,
        );
    }
}

/// Hold "no transfer with a banned member" after a room's ban list changes.
///
/// The owner's signed snapshot is how a device usually learns of an owner's ban,
/// and it arrives nowhere near the moderator-gossip path that ends these — so a
/// download from somebody the owner had just evicted carried on regardless, and
/// so did an upload of ours to them.
///
/// Reads the roster rather than diffing it, because the invariant is about who
/// is banned now and not about which row moved. Looping the ban list is fine at
/// this size: it is bounded by `CHANNEL_BAN_LIST_MAX`, the transfer maps hold a
/// handful of entries, and this only runs when a snapshot actually changed
/// something.
pub(super) fn drop_banned_channel_transfers(
    state: &mut NetworkState,
    db: &Database,
    app_handle: &tauri::AppHandle,
    channel_id: [u8; 16],
) {
    let channel_id_hex = hex::encode(channel_id);
    // Banned ourselves means none of the room's traffic is ours to carry, in
    // either direction, and their rows name us as the peer rather than
    // themselves — so a member-scoped sweep would find nothing.
    if db
        .channel_member_is_banned(&channel_id_hex, &hex::encode(state.local_ed25519_pubkey))
        .unwrap_or(false)
    {
        drop_channel_transfers_for(state, app_handle, channel_id, None, "not_allowed");
        return;
    }
    for peer in db
        .list_banned_channel_pubkeys(&channel_id_hex)
        .unwrap_or_default()
    {
        drop_channel_transfers_for(state, app_handle, channel_id, Some(peer), "not_allowed");
    }
}

pub(super) fn emit_xfer_update(
    app_handle: &tauri::AppHandle,
    xfer_id: &[u8; 16],
    channel_id: &[u8; 16],
    peer: &[u8; 32],
    direction: &str,
    name: &str,
    size: u64,
    transferred: u64,
    status: &str,
) {
    let _ = app_handle.emit(
        "ember:xfer-update",
        serde_json::json!({
            "xfer_id": hex::encode(xfer_id),
            "channel_id": hex::encode(channel_id),
            "peer_pubkey": hex::encode(peer),
            "direction": direction,
            "name": name,
            "size": size,
            "transferred": transferred,
            "status": status,
        }),
    );
}

/// Whether `peer` is allowed to put an offer in front of the user.
///
/// This gates the *prompt*, not the transfer — accepting is always a separate,
/// explicit act. So the permissive default costs at most a dialog you dismiss,
/// and the stricter settings exist for people who do not want even that.
pub(super) async fn xfer_offer_allowed(state: &NetworkState, peer: &[u8; 32]) -> bool {
    match state.xfer_offer_policy.as_str() {
        crate::types::CHANNEL_FILE_OFFERS_NOBODY => false,
        crate::types::CHANNEL_FILE_OFFERS_FRIENDS => {
            // Channel members and friends are the same identity keyed two
            // ways: a friend's Ember hash is BLAKE3 of this same pubkey.
            let hash = ember::channel::channel_id_from_pubkey(peer);
            state.xfer_friend_hashes.read().await.contains(&hash)
        }
        _ => true,
    }
}

/// Offers one member may have waiting on the user at once, across every room.
/// The sending side lets one member run this many transfers to one peer
/// (`OfferChannelTransfer`), so anything lower refuses a second file sent back
/// to back.
pub(super) const XFER_PENDING_PER_SENDER: usize = ember::channel::XFER_MAX_ACTIVE;

/// Offers waiting on the user at once, across every member and room.
pub(super) const XFER_PENDING_MAX: usize = ember::channel::XFER_MAX_ACTIVE * 2;

/// How long an offer is on screen before anything may displace it.
pub(super) const XFER_PENDING_MIN_DISPLAY: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum XferOfferAdmission {
    Admit,
    /// Admit, after dropping this pending offer to stay under the total.
    Evict([u8; 16]),
    Busy,
}

/// One pending offer, as [`xfer_offer_admission`] weighs it.
#[derive(Clone, Copy, Debug)]
pub(super) struct PendingOfferView {
    pub(super) xfer_id: [u8; 16],
    pub(super) peer: [u8; 32],
    pub(super) received_at: std::time::Instant,
    /// A sender whose identity cost something: a friend, a room's owner or
    /// moderator, or any member of a private room, where joining takes the key.
    pub(super) protected: bool,
}

/// Whether a new offer from `sender` fits beside the ones already pending.
///
/// A full table is settled in the newcomer's disfavour unless one of two
/// things is true, and even then only against an offer that has been on screen
/// for [`XFER_PENDING_MIN_DISPLAY`]:
/// - some other member holds at least two more offers than the newcomer
///   would, in which case their oldest goes — they keep the rest, so one
///   member cannot hold the table, but nobody is reduced to nothing; or
/// - the newcomer is protected and an unprotected offer is waiting, in which
///   case the oldest of those goes.
///
/// Identities in a public room are free, and beacons admit several a beat, so
/// anything looser let a stream of throwaway members evict every offer the
/// user was actually waiting on.
pub(super) fn xfer_offer_admission(
    pending: &[PendingOfferView],
    receiving: usize,
    sender: &[u8; 32],
    sender_protected: bool,
    now: std::time::Instant,
) -> XferOfferAdmission {
    if receiving >= ember::channel::XFER_MAX_ACTIVE {
        return XferOfferAdmission::Busy;
    }
    let mut held: HashMap<[u8; 32], usize> = HashMap::new();
    for offer in pending {
        *held.entry(offer.peer).or_default() += 1;
    }
    let ours = held.get(sender).copied().unwrap_or(0);
    if ours >= XFER_PENDING_PER_SENDER {
        return XferOfferAdmission::Busy;
    }
    if pending.len() < XFER_PENDING_MAX {
        return XferOfferAdmission::Admit;
    }
    let displayed =
        |offer: &PendingOfferView| now.saturating_duration_since(offer.received_at) >= XFER_PENDING_MIN_DISPLAY;
    let oldest = |candidates: &mut dyn Iterator<Item = &PendingOfferView>| {
        candidates
            .filter(|offer| displayed(offer))
            .min_by_key(|offer| (offer.received_at, offer.xfer_id))
            .map(|offer| offer.xfer_id)
    };
    let busiest = held
        .iter()
        .filter(|(peer, count)| *peer != sender && **count >= ours + 2)
        .map(|(_, count)| *count)
        .max();
    if let Some(most) = busiest {
        let mut theirs = pending
            .iter()
            .filter(|offer| offer.peer != *sender && held.get(&offer.peer) == Some(&most));
        if let Some(victim) = oldest(&mut theirs) {
            return XferOfferAdmission::Evict(victim);
        }
    }
    if sender_protected {
        let mut exposed = pending.iter().filter(|offer| !offer.protected);
        if let Some(victim) = oldest(&mut exposed) {
            return XferOfferAdmission::Evict(victim);
        }
    }
    XferOfferAdmission::Busy
}

/// Whether offers from `peer` in this room come from an identity that cost
/// something. See [`PendingOfferView::protected`].
fn xfer_sender_protected(
    state: &mut NetworkState,
    db: &Database,
    friends: &HashSet<[u8; 16]>,
    channel_id: [u8; 16],
    peer: &[u8; 32],
) -> bool {
    if friends.contains(&ember::channel::channel_id_from_pubkey(peer)) {
        return true;
    }
    let Some(view) = cached_channel_view(state, db, channel_id) else {
        return false;
    };
    view.row.visibility == ember::channel::CHANNEL_KIND_PRIVATE
        || view.row.owner_pubkey.eq_ignore_ascii_case(&hex::encode(peer))
        || channel_roster_snapshot(state, db, channel_id).is_moderator(peer)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_xfer_offer(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    ch: &crate::storage::database::StoredChannel,
    gossip: &ember::channel::ChannelGossip,
    offer: ember::channel::XferOffer,
    key: [u8; 32],
) {
    let sender_hex = hex::encode(offer.sender);
    if channel_member_banned(state, db, gossip.channel_id, &offer.sender) {
        return;
    }
    // Only someone we can see in the room may offer. Without this a member
    // who left, or was never here, could still put a dialog on screen.
    if !channel_member_pubkeys_cached(state, db, gossip.channel_id).contains(&offer.sender) {
        return;
    }
    // An offer costs the recipient a prompt, so it is rate-limited exactly
    // like a chat line from the same author.
    if !channel_author_gossip_ok(state, gossip.channel_id, &offer.sender) {
        forget_channel_gossip(state, &gossip.msg_id);
        return;
    }
    let name = crate::security::sanitize_filename(&offer.name);
    if name.is_empty() {
        return;
    }
    // First offer under a transfer id wins. The pairwise key is derived from the
    // id and not from the name, size or root, so the same sender could send a
    // second valid offer under an id already on screen: the prompt would then
    // describe one file while Accept fetched whichever one landed last, and a
    // reused id could park a pending offer beside a transfer already running.
    if state.xfer_pending.contains_key(&offer.xfer_id)
        || state.xfer_recv.contains_key(&offer.xfer_id)
        || state.xfer_send.contains_key(&offer.xfer_id)
    {
        debug!(
            "Ember channel xfer: ignoring a repeated offer for transfer {}",
            hex::encode(offer.xfer_id)
        );
        return;
    }

    let admission = {
        let friends_lock = state.xfer_friend_hashes.clone();
        let friends = friends_lock.read().await;
        let entries: Vec<([u8; 16], [u8; 16], [u8; 32], std::time::Instant)> = state
            .xfer_pending
            .iter()
            .map(|(id, p)| (*id, p.channel_id, p.peer, p.received_at))
            .collect();
        let pending: Vec<PendingOfferView> = entries
            .into_iter()
            .map(|(xfer_id, channel_id, peer, received_at)| PendingOfferView {
                xfer_id,
                peer,
                received_at,
                protected: xfer_sender_protected(state, db, &friends, channel_id, &peer),
            })
            .collect();
        let sender_protected =
            xfer_sender_protected(state, db, &friends, gossip.channel_id, &offer.sender);
        xfer_offer_admission(
            &pending,
            state.xfer_recv.len(),
            &offer.sender,
            sender_protected,
            std::time::Instant::now(),
        )
    };
    let refusal = if !xfer_offer_allowed(state, &offer.sender).await {
        Some(ember::channel::XferReply::NotAllowed)
    } else if offer.size > ember::channel::XFER_MAX_BYTES {
        Some(ember::channel::XferReply::TooLarge)
    } else if admission == XferOfferAdmission::Busy {
        Some(ember::channel::XferReply::Busy)
    } else {
        None
    };
    if let Some(reply) = refusal {
        let plain = ember::channel::encode_xfer_reply(
            &key,
            &state.local_ed25519_pubkey,
            &offer.sender,
            &offer.xfer_id,
            reply,
        );
        send_xfer_frame(socket, state, db, gossip.channel_id, offer.sender, &plain).await;
        return;
    }
    if let XferOfferAdmission::Evict(victim_id) = admission {
        if let Some(victim) = state.xfer_pending.remove(&victim_id) {
            // Told, so their side ends now rather than waiting out the stall
            // shed on an offer this device no longer holds.
            let plain = ember::channel::encode_xfer_reply(
                &victim.key,
                &state.local_ed25519_pubkey,
                &victim.peer,
                &victim_id,
                ember::channel::XferReply::Busy,
            );
            send_xfer_frame(socket, state, db, victim.channel_id, victim.peer, &plain).await;
            emit_xfer_update(
                app_handle,
                &victim_id,
                &victim.channel_id,
                &victim.peer,
                "receive",
                &victim.name,
                victim.size,
                0,
                "expired",
            );
        }
    }

    state.xfer_pending.insert(
        offer.xfer_id,
        ember::xfer::PendingOffer {
            channel_id: gossip.channel_id,
            peer: offer.sender,
            key,
            name: name.clone(),
            size: offer.size,
            root: offer.root,
            received_at: std::time::Instant::now(),
        },
    );
    let _ = app_handle.emit(
        "ember:xfer-offer",
        serde_json::json!({
            "xfer_id": hex::encode(offer.xfer_id),
            "channel_id": ch.channel_id,
            "peer_pubkey": sender_hex,
            "name": name,
            "size": offer.size,
        }),
    );
}

pub(super) async fn apply_xfer_reply(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    xfer_id: [u8; 16],
    sender: [u8; 32],
    reply: ember::channel::XferReply,
) {
    let Some(send) = state.xfer_send.get_mut(&xfer_id) else {
        return;
    };
    // Only the member we offered it to gets to answer.
    if send.peer != sender {
        return;
    }
    // An offer is answered once. Without this a second reply — a duplicate
    // that took the relay's slower path, or one forged by another member —
    // could tear down a transfer that is already running.
    if send.accepted {
        return;
    }
    if reply == ember::channel::XferReply::Accept {
        send.accepted = true;
        send.updated_at = std::time::Instant::now();
        emit_xfer_update(
            app_handle,
            &xfer_id,
            &send.channel_id,
            &send.peer,
            "send",
            &send.name,
            send.size,
            0,
            "accepted",
        );
        return;
    }
    let (channel_id, peer, name, size) = (send.channel_id, send.peer, send.name.clone(), send.size);
    state.xfer_send.remove(&xfer_id);
    emit_xfer_update(
        app_handle,
        &xfer_id,
        &channel_id,
        &peer,
        "send",
        &name,
        size,
        0,
        reply.as_str(),
    );
}

pub(super) fn apply_xfer_block_request(
    state: &mut NetworkState,
    xfer_id: [u8; 16],
    sender: [u8; 32],
    offset: u64,
    count: u16,
) {
    let Some(send) = state.xfer_send.get_mut(&xfer_id) else {
        return;
    };
    if send.peer != sender || !send.accepted {
        return;
    }
    send.enqueue(offset, count);
}

pub(super) fn apply_xfer_block_data(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    xfer_id: [u8; 16],
    sender: [u8; 32],
    offset: u64,
    data: &[u8],
) {
    let Some(recv) = state.xfer_recv.get_mut(&xfer_id) else {
        return;
    };
    if recv.peer != sender {
        return;
    }
    match recv.write_block(offset, data) {
        Ok(_) => {}
        Err(e) => {
            let (channel_id, peer, name, size) =
                (recv.channel_id, recv.peer, recv.name.clone(), recv.size);
            tracing::warn!(error = %e, "Ember Transfer: could not write an incoming block");
            if let Some(dead) = state.xfer_recv.remove(&xfer_id) {
                // Half a file helps nobody, and leaving it behind means the
                // download folder collects `.part` files nothing will finish.
                let _ = std::fs::remove_file(&dead.part_path);
            }
            emit_xfer_update(
                app_handle,
                &xfer_id,
                &channel_id,
                &peer,
                "receive",
                &name,
                size,
                0,
                "failed",
            );
            return;
        }
    }
    if let Some(_pct) = recv.progress_step() {
        let (channel_id, peer, name, size, done) = (
            recv.channel_id,
            recv.peer,
            recv.name.clone(),
            recv.size,
            recv.bytes_received(),
        );
        emit_xfer_update(
            app_handle,
            &xfer_id,
            &channel_id,
            &peer,
            "receive",
            &name,
            size,
            done,
            "active",
        );
    }
    if recv.is_complete() {
        finish_xfer_recv(state, xfer_id);
    }
}

/// `path`, or `name (2).ext` beside it if something is already there.
///
/// Two people sending you `photo.jpg` should give you two files, not one
/// overwritten one. Gives up after a bounded number of tries and returns the
/// last candidate, letting the rename fail rather than spinning.
pub(super) fn unique_download_path(path: &std::path::Path) -> std::path::PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_string();
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    let mut candidate = path.to_path_buf();
    for n in 2..1000u32 {
        let name = if ext.is_empty() {
            format!("{stem} ({n})")
        } else {
            format!("{stem} ({n}).{ext}")
        };
        candidate = parent.join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    candidate
}

/// Verify a finished download and move it into place.
///
/// The root is recomputed with the same [`ember::transfer::HashTree`] the
/// sender used, so "the file I have" and "the file you offered" are compared
/// by the same function rather than by two that merely agree today.
///
/// Verification reads and hashes the entire file — `XFER_MAX_BYTES` is 100 MB —
/// so it runs on the blocking pool and reports back through
/// `NetworkState::xfer_finish_tx`. Done inline it froze the network task for
/// the length of a whole-file read: every peer connection, DHT tick and
/// datagram the loop owns stalled behind one completing transfer, and on a cold
/// or spinning disk that is seconds, long enough to lose UDP to receive-buffer
/// overrun across every unrelated peer.
///
/// The `RecvState` is taken out of `xfer_recv` before the hash starts, so the
/// stall sweep in `drive_channel_transfers` cannot also retire it and a
/// duplicate final block cannot start a second verification of the same file.
pub(super) fn finish_xfer_recv(state: &mut NetworkState, xfer_id: [u8; 16]) {
    let Some(mut recv) = state.xfer_recv.remove(&xfer_id) else {
        return;
    };
    let tx = state.xfer_finish_tx.clone();
    state.xfer_finish_in_flight += 1;
    tokio::task::spawn_blocking(move || {
        let outcome = (|| -> std::io::Result<bool> {
            recv.finish()?;
            let file = std::fs::File::open(&recv.part_path)?;
            let tree = ember::transfer::HashTree::from_reader(std::io::BufReader::new(file))?;
            if tree.root_hash != recv.root {
                return Ok(false);
            }
            // Through the approved-root layer, like the eD2K completion path.
            // This used to be `create_dir_all` plus a `rename`, both by
            // pathname: a junction swapped in at `Downloads` was traversed, and
            // the peer's bytes landed wherever it pointed under a name the peer
            // also chose. `move_part_to_final_approved` re-pins the root, and
            // the recorded identity refuses a `.part` swapped underneath the
            // transfer.
            let target = unique_download_path(&recv.final_path);
            ed2k::transfer::move_part_to_final_approved(
                &recv.part_path,
                &target,
                &recv.download_root,
                &recv.part_identity,
            )
            .map_err(|e| std::io::Error::other(e.to_string()))?;
            Ok(true)
        })();
        let status = match outcome {
            Ok(true) => "complete",
            Ok(false) => {
                // Content did not match what was offered. Keep nothing.
                let _ = std::fs::remove_file(&recv.part_path);
                tracing::warn!(
                    "Ember Transfer: {} failed its hash check and was discarded",
                    recv.name
                );
                "failed"
            }
            Err(e) => {
                let _ = std::fs::remove_file(&recv.part_path);
                tracing::warn!(error = %e, "Ember Transfer: could not finalise {}", recv.name);
                "failed"
            }
        };
        let _ = tx.send(XferFinishResult {
            xfer_id,
            channel_id: recv.channel_id,
            peer: recv.peer,
            key: recv.key,
            name: recv.name,
            size: recv.size,
            status,
        });
    });
}

/// Tell the sender how a transfer ended and update the UI.
///
/// Split from [`finish_xfer_recv`] because the verification between them runs
/// off the event loop; this half needs the socket and the channel row, so it
/// runs in the loop's `xfer_finish_rx` arm once the verdict is in.
pub(super) async fn apply_xfer_finish(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    result: XferFinishResult,
) {
    state.xfer_finish_in_flight = state.xfer_finish_in_flight.saturating_sub(1);
    let complete = result.status == "complete";
    // Tell the sender how it ended either way. It has no other way to find
    // out: it answers requests and then hears nothing, so without this its
    // own stall timer would eventually report a finished transfer as failed.
    let plain = if complete {
        ember::channel::encode_xfer_done(
            &result.key,
            &state.local_ed25519_pubkey,
            &result.peer,
            &result.xfer_id,
        )
    } else {
        ember::channel::encode_xfer_cancel(
            &result.key,
            &state.local_ed25519_pubkey,
            &result.peer,
            &result.xfer_id,
            ember::channel::XferCancel::User,
        )
    };
    send_xfer_frame(socket, state, db, result.channel_id, result.peer, &plain).await;
    let done = if complete { result.size } else { 0 };
    emit_xfer_update(
        app_handle,
        &result.xfer_id,
        &result.channel_id,
        &result.peer,
        "receive",
        &result.name,
        result.size,
        done,
        result.status,
    );
}

/// The recipient has the whole file and it matched. Retire the send side.
pub(super) fn apply_xfer_done(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    xfer_id: [u8; 16],
    sender: [u8; 32],
) {
    let Some(send) = state.xfer_send.get(&xfer_id) else {
        return;
    };
    if send.peer != sender {
        return;
    }
    let send = state.xfer_send.remove(&xfer_id).expect("just checked");
    emit_xfer_update(
        app_handle,
        &xfer_id,
        &send.channel_id,
        &send.peer,
        "send",
        &send.name,
        send.size,
        send.size,
        "complete",
    );
}

pub(super) fn apply_xfer_cancel(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    xfer_id: [u8; 16],
    sender: [u8; 32],
    reason: ember::channel::XferCancel,
) {
    if let Some(pending) = state.xfer_pending.get(&xfer_id) {
        if pending.peer == sender {
            let pending = state.xfer_pending.remove(&xfer_id).expect("just checked");
            emit_xfer_update(
                app_handle,
                &xfer_id,
                &pending.channel_id,
                &pending.peer,
                "receive",
                &pending.name,
                pending.size,
                0,
                reason.as_str(),
            );
        }
        return;
    }
    if let Some(recv) = state.xfer_recv.get(&xfer_id) {
        if recv.peer != sender {
            return;
        }
        let recv = state.xfer_recv.remove(&xfer_id).expect("just checked");
        // Half a file is not a file. Nothing is left in the download folder.
        let _ = std::fs::remove_file(&recv.part_path);
        emit_xfer_update(
            app_handle,
            &xfer_id,
            &recv.channel_id,
            &recv.peer,
            "receive",
            &recv.name,
            recv.size,
            0,
            reason.as_str(),
        );
        return;
    }
    if let Some(send) = state.xfer_send.get(&xfer_id) {
        if send.peer != sender {
            return;
        }
        let send = state.xfer_send.remove(&xfer_id).expect("just checked");
        emit_xfer_update(
            app_handle,
            &xfer_id,
            &send.channel_id,
            &send.peer,
            "send",
            &send.name,
            send.size,
            0,
            reason.as_str(),
        );
    }
}

/// One pass of the transfer engine: answer block requests, top up the
/// receivers' request windows, and shed anything that has gone quiet.
pub(super) async fn drive_channel_transfers(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
) {
    if state.xfer_send.is_empty() && state.xfer_recv.is_empty() && state.xfer_pending.is_empty() {
        return;
    }
    let now = std::time::Instant::now();
    let me = state.local_ed25519_pubkey;

    // Offers nobody answered. Dropping them keeps a stale dialog from
    // accepting into a transfer the other side has long forgotten.
    let lapsed: Vec<[u8; 16]> = state
        .xfer_pending
        .iter()
        .filter(|(_, offer)| {
            now.saturating_duration_since(offer.received_at)
                > std::time::Duration::from_secs(ember::channel::XFER_OFFER_TTL_SECS as u64)
        })
        .map(|(id, _)| *id)
        .collect();
    for xfer_id in lapsed {
        if let Some(offer) = state.xfer_pending.remove(&xfer_id) {
            emit_xfer_update(
                app_handle,
                &xfer_id,
                &offer.channel_id,
                &offer.peer,
                "receive",
                &offer.name,
                offer.size,
                0,
                "expired",
            );
        }
    }

    // Answer whatever the far ends have asked for, within this tick's budget.
    let senders: Vec<[u8; 16]> = state
        .xfer_send
        .iter()
        .filter(|(_, send)| send.has_work())
        .map(|(id, _)| *id)
        .collect();
    // Labelled so running out of send budget breaks out to the receive side
    // below rather than returning. A node doing both at once would otherwise
    // stop asking for its own blocks whenever it was busy answering someone
    // else's, and the two transfers would take turns stalling each other.
    'sending: for xfer_id in senders {
        // Everything the block needs is copied out while the borrow is live,
        // so the body below is free to touch `state` again for the send.
        while let Some((block, channel_id, peer, key, size)) =
            state.xfer_send.get_mut(&xfer_id).and_then(|send| {
                if !send.has_work() {
                    return None;
                }
                let block = send.next_block()?;
                Some((block, send.channel_id, send.peer, send.key, send.size))
            })
        {
            if !xfer_block_rate_ok(state) {
                // Out of budget for this tick. Put the block back so the next
                // tick picks it up rather than dropping it on the floor — the
                // old path abandoned the rest of the file here, which is
                // precisely why attachments never finished.
                if let Some(send) = state.xfer_send.get_mut(&xfer_id) {
                    send.enqueue(block, 1);
                }
                break 'sending;
            }
            let offset = block * ember::channel::XFER_BLOCK_SIZE as u64;
            let want = ((size - offset) as usize).min(ember::channel::XFER_BLOCK_SIZE);
            // Room transfers spend the user's upload cap like eD2K uploads do.
            // Only the protocol's own block-rate window used to bound them, so a
            // configured limit did nothing here and an attachment could saturate
            // a connection the user had explicitly throttled.
            //
            // Allowance is accumulated rather than waited for: this runs on the
            // network event loop, so parking on the limiter would stall KAD, IPC
            // and the DHT with it. Carrying the shortfall between ticks is also
            // what lets a cap below one frame pace instead of deadlock.
            if !xfer_upload_allowance_ok(state, bandwidth_limiter, want as u64) {
                if let Some(send) = state.xfer_send.get_mut(&xfer_id) {
                    send.enqueue(block, 1);
                }
                break 'sending;
            }
            let read = state
                .xfer_send
                .get_mut(&xfer_id)
                .map(|send| send.read_block(offset, want));
            let Some(Ok(buf)) = read else {
                // The file moved or became unreadable mid-transfer. Say so
                // rather than letting the other end time out guessing.
                let plain = ember::channel::encode_xfer_cancel(
                    &key,
                    &me,
                    &peer,
                    &xfer_id,
                    ember::channel::XferCancel::SourceGone,
                );
                send_xfer_frame(socket, state, db, channel_id, peer, &plain).await;
                if let Some(send) = state.xfer_send.remove(&xfer_id) {
                    emit_xfer_update(
                        app_handle,
                        &xfer_id,
                        &channel_id,
                        &peer,
                        "send",
                        &send.name,
                        send.size,
                        0,
                        "source_gone",
                    );
                }
                continue 'sending;
            };
            let Some(plain) =
                ember::channel::encode_xfer_block_data(&key, &me, &peer, &xfer_id, offset, &buf)
            else {
                break;
            };
            send_xfer_frame(socket, state, db, channel_id, peer, &plain).await;
            if let Some(send) = state.xfer_send.get_mut(&xfer_id) {
                send.note_sent();
                if let Some(_pct) = send.progress_step() {
                    let (name, sent) = (send.name.clone(), send.bytes_sent());
                    emit_xfer_update(
                        app_handle,
                        &xfer_id,
                        &channel_id,
                        &peer,
                        "send",
                        &name,
                        size,
                        sent,
                        "active",
                    );
                }
            }
        }
    }

    // Top up each receiver's window.
    let receivers: Vec<[u8; 16]> = state.xfer_recv.keys().copied().collect();
    for xfer_id in receivers {
        let Some(recv) = state.xfer_recv.get_mut(&xfer_id) else {
            continue;
        };
        let (channel_id, peer, key) = (recv.channel_id, recv.peer, recv.key);
        let runs = recv.next_requests(now);
        for (start, count) in runs {
            let plain =
                ember::channel::encode_xfer_block_request(&key, &me, &peer, &xfer_id, start, count);
            send_xfer_frame(socket, state, db, channel_id, peer, &plain).await;
        }
    }

    // Shed transfers that have gone quiet in either direction.
    let stalled_send: Vec<[u8; 16]> = state
        .xfer_send
        .iter()
        .filter(|(_, send)| send.is_stalled(now))
        .map(|(id, _)| *id)
        .collect();
    for xfer_id in stalled_send {
        if let Some(send) = state.xfer_send.remove(&xfer_id) {
            let plain = ember::channel::encode_xfer_cancel(
                &send.key,
                &me,
                &send.peer,
                &xfer_id,
                ember::channel::XferCancel::Stalled,
            );
            send_xfer_frame(socket, state, db, send.channel_id, send.peer, &plain).await;
            emit_xfer_update(
                app_handle,
                &xfer_id,
                &send.channel_id,
                &send.peer,
                "send",
                &send.name,
                send.size,
                send.bytes_sent(),
                // Nobody ever answered, versus a transfer that started and
                // then went quiet. The two read very differently to whoever
                // offered the file.
                if send.accepted { "stalled" } else { "expired" },
            );
        }
    }
    let stalled_recv: Vec<[u8; 16]> = state
        .xfer_recv
        .iter()
        .filter(|(_, recv)| recv.is_stalled(now))
        .map(|(id, _)| *id)
        .collect();
    for xfer_id in stalled_recv {
        if let Some(recv) = state.xfer_recv.remove(&xfer_id) {
            // Detached: nothing below depends on the delete landing, and on
            // Windows removing a large file whose handle was just released
            // blocks on the antivirus filter driver — on the network task,
            // once per stalled transfer.
            let part_path = recv.part_path.clone();
            tokio::task::spawn_blocking(move || {
                let _ = std::fs::remove_file(&part_path);
            });
            let plain = ember::channel::encode_xfer_cancel(
                &recv.key,
                &me,
                &recv.peer,
                &xfer_id,
                ember::channel::XferCancel::Stalled,
            );
            send_xfer_frame(socket, state, db, recv.channel_id, recv.peer, &plain).await;
            emit_xfer_update(
                app_handle,
                &xfer_id,
                &recv.channel_id,
                &recv.peer,
                "receive",
                &recv.name,
                recv.size,
                0,
                "stalled",
            );
        }
    }
}

#[cfg(test)]
mod xfer_offer_admission_tests {
    use super::{
        xfer_offer_admission, PendingOfferView, XferOfferAdmission, XFER_PENDING_MAX,
        XFER_PENDING_MIN_DISPLAY, XFER_PENDING_PER_SENDER,
    };
    use crate::network::ember::channel::XFER_MAX_ACTIVE;
    use std::time::{Duration, Instant};

    fn member(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    fn offer(n: u8, peer: u8, received_at: Instant, protected: bool) -> PendingOfferView {
        PendingOfferView {
            xfer_id: id(n),
            peer: member(peer),
            received_at,
            protected,
        }
    }

    /// Long enough ago that nothing is still inside its minimum display time.
    fn shown(now: Instant, extra_secs: u64) -> Instant {
        now - XFER_PENDING_MIN_DISPLAY - Duration::from_secs(extra_secs)
    }

    /// The sender allows `XFER_MAX_ACTIVE` transfers to one peer, so a second
    /// file sent right after the first must not come back busy.
    #[test]
    fn back_to_back_offers_from_one_member_are_admitted_up_to_the_sender_cap() {
        const _: () = assert!(XFER_PENDING_PER_SENDER >= 2);
        let now = Instant::now();
        let mut pending = Vec::new();
        for i in 0..XFER_PENDING_PER_SENDER as u8 {
            assert_eq!(
                xfer_offer_admission(&pending, 0, &member(1), false, now),
                XferOfferAdmission::Admit
            );
            pending.push(offer(i, 1, now, false));
        }
        assert_eq!(
            xfer_offer_admission(&pending, 0, &member(1), false, now),
            XferOfferAdmission::Busy
        );
    }

    fn full_of_singletons(now: Instant, protected: bool) -> Vec<PendingOfferView> {
        (0..XFER_PENDING_MAX as u8)
            .map(|i| offer(i, 10 + i, shown(now, u64::from(XFER_PENDING_MAX as u8 - i)), protected))
            .collect()
    }

    /// Cheap identities cannot clear the table: a newcomer who is not
    /// protected is refused rather than displacing anybody's only offer.
    #[test]
    fn an_unprotected_newcomer_is_refused_rather_than_evicting() {
        let now = Instant::now();
        let pending = full_of_singletons(now, false);
        assert_eq!(
            xfer_offer_admission(&pending, 0, &member(99), false, now),
            XferOfferAdmission::Busy
        );
    }

    #[test]
    fn a_protected_newcomer_displaces_the_oldest_unprotected_offer() {
        let now = Instant::now();
        let mut pending = full_of_singletons(now, false);
        pending[0].protected = true;
        assert_eq!(
            xfer_offer_admission(&pending, 0, &member(99), true, now),
            XferOfferAdmission::Evict(id(1)),
            "the oldest offer is protected, so the next oldest goes"
        );
    }

    #[test]
    fn protected_offers_are_never_evicted_for_anybody() {
        let now = Instant::now();
        let pending = full_of_singletons(now, true);
        assert_eq!(
            xfer_offer_admission(&pending, 0, &member(99), true, now),
            XferOfferAdmission::Busy
        );
    }

    /// Nothing is displaced before it has been on screen for the minimum.
    #[test]
    fn a_fresh_offer_is_not_evicted() {
        let now = Instant::now();
        let pending: Vec<_> = (0..XFER_PENDING_MAX as u8)
            .map(|i| offer(i, 10 + i, now, false))
            .collect();
        assert_eq!(
            xfer_offer_admission(&pending, 0, &member(99), true, now),
            XferOfferAdmission::Busy
        );
    }

    /// One member holding the table gives way, protected or not, but only
    /// down to where they still hold more than the newcomer.
    #[test]
    fn a_member_holding_the_most_gives_up_their_oldest() {
        let now = Instant::now();
        let mut pending = Vec::new();
        let mut n = 0u8;
        for peer in [1u8, 2] {
            for i in 0..XFER_PENDING_PER_SENDER as u64 {
                pending.push(offer(n, peer, shown(now, 100 - i - u64::from(peer) * 10), true));
                n += 1;
            }
        }
        assert_eq!(pending.len(), XFER_PENDING_MAX);
        // Both hold the most, so the oldest of their offers goes — member 1's
        // first, which carries the largest age offset.
        assert_eq!(
            xfer_offer_admission(&pending, 0, &member(3), false, now),
            XferOfferAdmission::Evict(id(0))
        );
        // A member holding only one fewer than the busiest gains nothing by
        // evicting: they would end up level with the member they displaced.
        let mut close = pending.clone();
        close.retain(|o| o.peer == member(1));
        for i in 0..(XFER_PENDING_MAX - XFER_PENDING_PER_SENDER - (XFER_PENDING_PER_SENDER - 1)) as u8 {
            close.push(offer(200 + i, 50 + i, shown(now, 0), false));
        }
        for i in 0..(XFER_PENDING_PER_SENDER - 1) as u8 {
            close.push(offer(220 + i, 3, shown(now, 0), false));
        }
        assert_eq!(close.len(), XFER_PENDING_MAX);
        assert_eq!(
            xfer_offer_admission(&close, 0, &member(3), false, now),
            XferOfferAdmission::Busy
        );
    }

    #[test]
    fn active_receives_still_bound_new_offers() {
        assert_eq!(
            xfer_offer_admission(&[], XFER_MAX_ACTIVE, &member(1), true, Instant::now()),
            XferOfferAdmission::Busy
        );
    }
}

