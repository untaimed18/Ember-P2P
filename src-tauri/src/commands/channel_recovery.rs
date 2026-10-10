//! Finding the rooms this identity owns again.
//!
//! A room this identity owns has a seed derived from the identity and a random
//! salt ([`channel::derive_owned_room_seed`]), and the identity keeps a signed
//! list of those salts on the network ([`channel::owned_rooms_key`]). A device
//! that has the identity — restored from any backup, however old — reads the
//! list, works out every room in it, and looks each one up. What the network
//! still holds of a room is enough to run it again: the owner's signed
//! governance snapshot (topic, bans, moderators, the key the room seals with
//! now) and, for a private room that has rotated, the owner's own sealed copy
//! of that key.
//!
//! The salts are random so that nothing here ever has to decide a room key is
//! unused: the worst a lost or withheld list can do is leave a room behind,
//! never give a second room the keys of a first. For the same reason every
//! list found is merged rather than the newest taken: a salt whose room is
//! gone costs one lookup and is dropped.

use std::collections::HashSet;

use tauri::{Emitter, Manager};

use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
use crate::network::channel_membership::{ChannelEpochIngest, RestoringRoom};
use crate::network::ember::channel::{
    self, ChannelIdentity, OwnedRoomSalt, CHANNEL_KIND_PRIVATE, CHANNEL_KIND_PUBLIC,
};
use crate::network::ember::dht::publish::{
    ChannelModeration, SignedRecord, CHANNEL_KIND_INDEX, RECORD_TYPE_CHANNEL,
};
use crate::network::NetworkCommand;
use crate::storage::database::{Database, RecoveredChannel};

/// How long one lookup may take before its answer counts as unknown.
const PROBE_TIMEOUT_MS: u64 = 12_000;
/// Nodes that must have answered a lookup that found nothing before it is
/// taken to mean nothing is there. Counted from the walk itself, not from the
/// routing table, which can be full of contacts that left while this device
/// was off — a walk none of them answer finishes just as empty.
const MIN_RESPONDERS_FOR_ABSENCE: usize = 4;
/// Rooms looked up at once: a few lookups each, inside the background search
/// pool without crowding out everything else that uses it.
const PROBE_BATCH: usize = 3;
/// How long a recovered private room waits for our own sealed copy of its
/// current key, with the network saying it holds none, before it is given a
/// fresh key instead. Long enough that a storer briefly out of reach does not
/// cost the room a rotation.
const OWNER_KEY_GIVE_UP_SECS: i64 = 3 * 86_400;
/// Epochs past the one a snapshot names that are looked for too: a storer
/// that missed the owner's last snapshots still serves an earlier one, and our
/// own copy of each later key says the room moved on.
const OWN_EPOCH_LOOKAHEAD: i64 = 4;
/// How often rooms that could not be settled are looked at again while
/// Ember runs. Before their snapshots lapse, and well before members start
/// counting the owner as gone.
const UNSETTLED_RETRY_SECS: u64 = 6 * 60 * 60;

/// Emitted when a look put rooms back: `{ "count": n }`.
pub const CHANNELS_RECOVERED_EVENT: &str = "ember:channels-recovered";

/// One look at a time: the startup look, Settings, and a second click would
/// otherwise each walk the same rooms and fill the search pool together.
fn scan_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// What a look found.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct OwnedRoomScan {
    /// Rooms put back on this device, or made ours again.
    pub recovered: u32,
    /// The identity's list was read, so this device may publish its own.
    /// False when the network could not be reached well enough to be sure;
    /// the look is worth repeating then.
    pub confirmed: bool,
    /// Rooms in the list that could not be settled this time. They stay
    /// listed and are looked at again.
    pub unsettled: u32,
}

enum Probe {
    /// What came back, and whether enough of the network answered for what
    /// is missing from it to count as missing.
    Found(Vec<Vec<u8>>, bool),
    Absent,
    Unknown,
}

impl Probe {
    fn records(&self) -> &[Vec<u8>] {
        match self {
            Probe::Found(records, _) => records,
            _ => &[],
        }
    }

    /// Whether enough of the network answered for what this did not return
    /// to count as not there. Anyone can file records under any key, so a few
    /// nodes returning something is no better than a few returning nothing.
    fn settles_absence(&self) -> bool {
        matches!(self, Probe::Absent | Probe::Found(_, true))
    }
}

/// One DHT lookup, told apart into "here", "not here" and "cannot say".
async fn probe(state: &AppState, key: [u8; 16]) -> Probe {
    let (tx, rx) = tokio::sync::oneshot::channel();
    if state
        .network_tx
        .try_send(NetworkCommand::FindEmberKeys { keys: vec![key], tx })
        .is_err()
    {
        return Probe::Unknown;
    }
    let pending = match tokio::time::timeout(
        std::time::Duration::from_millis(PROBE_TIMEOUT_MS),
        rx,
    )
    .await
    {
        Ok(Ok(Ok(pending))) => pending,
        _ => return Probe::Unknown,
    };
    let responded = pending.responded.clone();
    let enough = || {
        responded.load(std::sync::atomic::Ordering::Acquire) >= MIN_RESPONDERS_FOR_ABSENCE
    };
    match tokio::time::timeout(
        std::time::Duration::from_millis(PROBE_TIMEOUT_MS),
        pending.records_rx,
    )
    .await
    {
        Ok(Ok(records)) if !records.is_empty() => Probe::Found(records, enough()),
        Ok(Ok(_)) if enough() => Probe::Absent,
        Ok(_) => Probe::Unknown,
        Err(_) => {
            let _ = state.network_tx.try_send(NetworkCommand::CancelEmberSearch {
                search_id: pending.search_id,
            });
            Probe::Unknown
        }
    }
}

/// The newest governance snapshot the room's own key signed, if any.
fn newest_moderation(records: &[Vec<u8>], ident: &ChannelIdentity) -> Option<ChannelModeration> {
    records
        .iter()
        .filter_map(|blob| SignedRecord::parse_channel_moderation(blob, &ident.channel_id))
        .filter(|m| m.publisher_key == ident.pubkey)
        .reduce(|best, next| {
            if crate::network::ember::dht::publish::moderation_supersedes(
                next.timestamp,
                &next.signature,
                best.timestamp,
                Some(&best.signature),
            ) {
                next
            } else {
                best
            }
        })
}

/// Whether the room's own key signed a handoff away from it: proof the room
/// to run is another, since only the owner holds that key.
fn handed_off(handoffs: &[Vec<u8>], ident: &ChannelIdentity) -> bool {
    handoffs.iter().any(|blob| {
        SignedRecord::parse_channel_handoff(blob, &ident.channel_id)
            .is_some_and(|handoff| handoff.publisher_key == ident.pubkey)
    })
}

/// Whether the nominee the room's newest snapshot names has claimed it after
/// the owner's silence. Anyone can sign a claim, so one from anybody else is
/// no evidence of anything — and even the nominee's only holds the room back
/// rather than dropping it, since whether the silence was long enough is the
/// members' call.
fn nominee_claimed(claims: &[Vec<u8>], ident: &ChannelIdentity, snapshot: &ChannelModeration) -> bool {
    let Some(nominee) = snapshot.tail.successor_nominee.filter(|n| *n != [0u8; 32]) else {
        return false;
    };
    claims.iter().any(|blob| {
        SignedRecord::parse_channel_succession_claim(blob, &ident.channel_id)
            .is_some_and(|(claimant, ..)| claimant == nominee)
    })
}

/// The name a public room is listed under, from its own signed listing.
fn listed_name(records: &[Vec<u8>], ident: &ChannelIdentity) -> Option<String> {
    records.iter().find_map(|blob| {
        let rec = SignedRecord::from_value_blob(blob)?;
        let meta = rec.channel.as_ref()?;
        (rec.record_type == RECORD_TYPE_CHANNEL
            && rec.file_hash == ident.channel_id
            && rec.publisher_key == ident.pubkey
            && meta.kind == CHANNEL_KIND_INDEX
            && rec.channel_store_ok())
        .then(|| rec.file_name.trim().to_string())
        .filter(|name| !name.is_empty())
    })
}

/// Every salt in every list this identity signed that came back.
fn merged_lists(records: &[Vec<u8>], identity_pubkey: &[u8; 32]) -> Option<Vec<OwnedRoomSalt>> {
    let mut salts: Vec<OwnedRoomSalt> = Vec::new();
    let mut any = false;
    for (listed, _) in records
        .iter()
        .filter_map(|blob| SignedRecord::parse_owned_rooms(blob, identity_pubkey))
    {
        any = true;
        for salt in listed {
            if !salts.contains(&salt) {
                salts.push(salt);
            }
        }
    }
    any.then_some(salts)
}

/// What one listed room turned out to be.
enum Slot {
    /// Held here with its seed already; waiting on its current key since the
    /// given time, if it is.
    Held(Option<(i64, i64)>),
    /// Gone for good: deleted here, or handed on by the room's own key.
    Gone,
    /// Listed as deleted by the registry. Not put back, but carried until its
    /// salt lapses rather than dropped: the list is the server's word, not
    /// the room key's.
    Withheld,
    /// Here is its newest governance snapshot.
    Live(Box<ChannelModeration>, Vec<Vec<u8>>),
    /// Could not be settled this time.
    Unsettled,
}

async fn examine(
    state: &AppState,
    ident: &ChannelIdentity,
    deleted: Option<&HashSet<String>>,
) -> Slot {
    let id_hex = hex::encode(ident.channel_id);
    let held = {
        let id = id_hex.clone();
        let db = state.db.clone();
        tokio::task::spawn_blocking(move || {
            Ok::<_, anyhow::Error>((
                db.get_channel(&id)?,
                db.load_channel_owner_seed(&id)?,
                db.channel_owner_key_pending_since(&id)?,
            ))
        })
        .await
    };
    match held {
        Ok(Ok((Some(row), _, _))) if row.deleted || !row.successor_id.is_empty() => return Slot::Gone,
        // Left alone even if the registry lists it as deleted: that list is
        // the server's word, not the room key's, and is only trusted to keep a
        // room from coming back, never to put out one this device runs.
        Ok(Ok((Some(_), Some(_), pending))) => return Slot::Held(pending),
        Ok(Ok(_)) => {}
        _ => return Slot::Unsettled,
    }
    if deleted.is_some_and(|ids| ids.contains(&id_hex)) {
        return Slot::Withheld;
    }
    // Twice for the snapshot, from two walks, and the newer kept: a node that
    // missed the owner's later stores still serves an earlier one, and the
    // epoch in an older snapshot is one the room has already moved past.
    let (first, second, handoff, claim) = tokio::join!(
        probe(state, channel::moderation_key(&ident.channel_id)),
        probe(state, channel::moderation_key(&ident.channel_id)),
        probe(state, channel::handoff_key(&ident.channel_id)),
        probe(state, channel::claim_key(&ident.channel_id)),
    );
    if handed_off(handoff.records(), ident) {
        return Slot::Gone;
    }
    // Without both answers a room handed on, or taken over, could be run
    // again as if it never was.
    if !handoff.settles_absence() || !claim.settles_absence() {
        return Slot::Unsettled;
    }
    // One walk that reached few nodes can return a snapshot the owner has
    // since replaced, and the owner loop would re-sign that older state.
    if !first.settles_absence() && !second.settles_absence() {
        return Slot::Unsettled;
    }
    let mut records = first.records().to_vec();
    records.extend_from_slice(second.records());
    let Some(snapshot) = newest_moderation(&records, ident) else {
        return Slot::Unsettled;
    };
    if nominee_claimed(claim.records(), ident, &snapshot) {
        return Slot::Unsettled;
    }
    // The registry list is what says a room was deleted once its records
    // lapse; without it a room is not put back, only carried for later.
    if deleted.is_none() {
        return Slot::Unsettled;
    }
    Slot::Live(Box::new(snapshot), records)
}

/// Put one room back from its snapshot. Returns whether anything changed.
#[allow(clippy::too_many_arguments)]
async fn restore_room(
    state: &AppState,
    app: Option<&tauri::AppHandle>,
    salt: OwnedRoomSalt,
    seed: [u8; 32],
    ident: &ChannelIdentity,
    snapshot: &ChannelModeration,
    records: &[Vec<u8>],
) -> Result<bool, String> {
    let id_hex = hex::encode(ident.channel_id);
    let private = snapshot.private;
    // Every snapshot this build signs names the room. One from before that
    // may not: a public room's listing names it too, and otherwise only its
    // members and the name registry know — neither of which this device can
    // ask by room. The stand-in is held back from everything the owner signs
    // until the owner renames the room; members keep the name they have.
    let known_name = match snapshot.tail.room_name.clone() {
        Some(name) if !name.trim().is_empty() => Some(name),
        _ if !private => match probe(state, channel::index_key_for_channel(&ident.channel_id)).await {
            Probe::Found(records, _) => listed_name(&records, ident),
            Probe::Absent => None,
            // Asked and not answered is not "unnamed": a stand-in would stop
            // the listing and the name claim being renewed for good.
            Probe::Unknown => {
                return Err(coded(
                    "channels_recover_unavailable",
                    "Could not reach enough of the network to read the room's listing",
                ))
            }
        },
        _ => None,
    };
    let name_unknown = known_name.is_none();
    let name = known_name.clone().unwrap_or_else(|| placeholder_name(&id_hex));
    // Right for every room this identity created. A room it took over keeps
    // the key it inherited, but rotates away from it straight after, and its
    // current key comes back from our own sealed copy below.
    let join_secret = private.then(|| channel::derive_owned_join_secret(&seed));
    let visibility = if private { CHANNEL_KIND_PRIVATE } else { CHANNEL_KIND_PUBLIC };
    let epoch = snapshot.tail.key_epoch.unwrap_or(0).min(i64::MAX as u64) as i64;
    // The owner loop and every owner tool keep off the room until its
    // snapshot is on it: before, they would sign one with no bans, no topic
    // and an old key, newer than the real one and so outranking it.
    let _restoring = RestoringRoom::begin(&id_hex);
    let outcome = {
        let db = state.db.clone();
        let id = id_hex.clone();
        let pk = hex::encode(ident.pubkey);
        let records = records.to_vec();
        let channel_id = ident.channel_id;
        let snapshot_ts = snapshot.timestamp;
        tokio::task::spawn_blocking(move || {
            let outcome = db.adopt_recovered_owned_channel(
                &id,
                &pk,
                &name,
                visibility,
                &seed,
                join_secret.as_ref(),
                &salt,
            )?;
            if matches!(outcome, RecoveredChannel::Inserted | RecoveredChannel::Adopted) {
                // Not waiting on a key that is already here, as it is for a
                // room we held as a member, which would then wait for ever.
                let held = db
                    .load_channel_key_epochs(&id)?
                    .into_iter()
                    .map(|(e, _)| e)
                    .max()
                    .unwrap_or(0);
                if private && epoch > held {
                    db.mark_channel_owner_key_pending(&id, epoch)?;
                }
                if name_unknown && outcome == RecoveredChannel::Inserted {
                    db.mark_channel_name_unconfirmed(&id)?;
                }
                crate::network::channel_membership::ingest_channel_moderation_records(
                    &db,
                    channel_id,
                    &records,
                );
                // The governance has to be on the room before anything signs
                // for it: otherwise, once the restore guard drops, the owner
                // loop republishes a snapshot with no bans and no topic that
                // outranks the real one. "Not newer" is fine for a room held as
                // a member, which already had it; only a room still behind the
                // snapshot found is a failure. Given back, it is looked at
                // again on the next scan.
                let governed = db
                    .get_channel(&id)?
                    .is_some_and(|row| row.moderation_updated_at >= snapshot_ts);
                if !governed {
                    db.release_recovered_owned_channel(&id, outcome)?;
                    anyhow::bail!("the room's governance snapshot did not apply");
                }
                // Ingest leaves an owner's own name alone, which for a room we
                // held as a member is the name its invite gave it; the owner's
                // snapshot is the one to keep.
                if outcome == RecoveredChannel::Adopted {
                    if let Some(name) = known_name.as_deref() {
                        db.apply_owner_room_name(&id, name)?;
                    }
                }
            }
            Ok::<_, anyhow::Error>(outcome)
        })
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("channels_recover_failed", "Could not restore a room", e))?
    };
    if !matches!(outcome, RecoveredChannel::Inserted | RecoveredChannel::Adopted) {
        return Ok(false);
    }
    tracing::info!(channel_id = %id_hex, ?outcome, "restored a room this identity owns");
    if private {
        catch_up_own_epochs(state, ident, epoch.max(1)).await;
    }
    drop(_restoring);
    enter_if_ready(state, &id_hex).await;
    let _ = state.network_tx.try_send(NetworkCommand::RefreshChannelMembers {
        channel_id: ident.channel_id,
    });
    if let Some(app) = app {
        let _ = app.emit(
            "ember:channel-moderation",
            serde_json::json!({ "channel_id": id_hex }),
        );
    }
    Ok(true)
}

/// Back in the room under our username — once the room's current key is
/// here. Before it, presence would be published under a key the room has
/// left, which only the members it evicted can read; the room is already
/// marked as ours and inside, and its presence follows the key.
async fn enter_if_ready(state: &AppState, id_hex: &str) {
    let waiting = {
        let db = state.db.clone();
        let id = id_hex.to_string();
        tokio::task::spawn_blocking(move || db.channel_owner_key_pending(&id))
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten()
            .is_some()
    };
    if waiting {
        return;
    }
    if let Ok(username) = crate::commands::channels::require_channel_username(state).await {
        if let Err(e) = crate::commands::channels::enter_stored_channel(state, id_hex, &username).await {
            tracing::debug!(channel_id = %id_hex, error = %e, "restored room not entered yet");
        }
    }
}

/// What looking for our own sealed copy of a key found.
enum OwnCopy {
    Fetched,
    Absent,
    Unknown,
}

/// Fetch our own sealed copies of the room's keys from `from` on, now rather
/// than at the next pass of the key loop, which also keeps trying. Goes on
/// past `from` while later copies turn up, for a snapshot served stale.
/// Reports on `from` itself.
async fn catch_up_own_epochs(state: &AppState, ident: &ChannelIdentity, from: i64) -> OwnCopy {
    let mut first = OwnCopy::Unknown;
    for epoch in from..from.saturating_add(OWN_EPOCH_LOOKAHEAD + 1) {
        let key = channel::epoch_key(&ident.channel_id, &state.identity.ed25519_public_key, epoch);
        let found = match probe(state, key).await {
            Probe::Found(records, _) => {
                let db = state.db.clone();
                let identity = state.identity.clone();
                let channel_id = ident.channel_id;
                let ingested = tokio::task::spawn_blocking(move || {
                    crate::network::channel_membership::ingest_channel_epoch_records(
                        &db, &identity, channel_id, epoch, &records,
                    )
                })
                .await;
                matches!(ingested, Ok(ChannelEpochIngest::Rekeyed))
            }
            Probe::Absent => {
                if epoch == from {
                    first = OwnCopy::Absent;
                }
                false
            }
            Probe::Unknown => false,
        };
        if !found {
            break;
        }
        if epoch == from {
            first = OwnCopy::Fetched;
        }
    }
    first
}

/// A room held here that is still waiting on its current key: fetch it, or
/// once the network has said for long enough that it holds no copy for us,
/// give the room a fresh key. Returns whether it is still waiting.
async fn resume_waiting_room(state: &AppState, ident: &ChannelIdentity, epoch: i64, since: i64) -> bool {
    let id_hex = hex::encode(ident.channel_id);
    match catch_up_own_epochs(state, ident, epoch).await {
        OwnCopy::Fetched => {}
        OwnCopy::Absent if chrono::Utc::now().timestamp() - since >= OWNER_KEY_GIVE_UP_SECS => {
            match crate::commands::channels::rekey_recovered_room(state, &id_hex, epoch).await {
                Ok(next) => tracing::warn!(
                    channel_id = %id_hex,
                    "no copy of the room's key {epoch} came back; gave it a fresh one at {next}"
                ),
                Err(e) => tracing::debug!(channel_id = %id_hex, error = %e, "could not re-key a recovered room yet"),
            }
        }
        _ => {}
    }
    let still = {
        let db = state.db.clone();
        let id = id_hex.clone();
        tokio::task::spawn_blocking(move || db.channel_owner_key_pending(&id))
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten()
            .is_some()
    };
    if !still {
        enter_if_ready(state, &id_hex).await;
    }
    still
}

fn placeholder_name(id_hex: &str) -> String {
    format!("Room {}", &id_hex[..8.min(id_hex.len())])
}

/// The identity's list, from two walks merged: one that reached only nodes
/// holding an older copy would otherwise miss the rooms made since. `None`
/// when the network could not say.
async fn read_owned_rooms_list(state: &AppState) -> Option<Vec<OwnedRoomSalt>> {
    let our_pk = state.identity.ed25519_public_key;
    let key = channel::owned_rooms_key(&our_pk);
    let (first, second) = tokio::join!(probe(state, key), probe(state, key));
    let mut records = first.records().to_vec();
    records.extend_from_slice(second.records());
    if let Some(salts) = merged_lists(&records, &our_pk) {
        return Some(salts);
    }
    // Nothing that is a list: no list yet, but only on enough of the
    // network's word.
    (first.settles_absence() || second.settles_absence()).then(Vec::new)
}

/// Read the identity's owned-rooms list, put back every room in it that the
/// network still holds and this device does not, and let this device publish
/// its own list once the network's has been read.
pub(crate) async fn scan_owned_rooms(
    state: &AppState,
    app: Option<&tauri::AppHandle>,
) -> Result<OwnedRoomScan, String> {
    let _single = scan_lock().lock().await;
    if state.db.chat_locked() {
        return Err(coded(
            "channels_chat_locked",
            "Chat history is locked; restore the key file to manage channels",
        ));
    }
    if !state.config.read().await.settings.ember_native_enabled {
        return Err(coded("channels_ember_disabled", "Ember-native transport is disabled"));
    }
    let Some(listed) = read_owned_rooms_list(state).await else {
        return Err(coded(
            "channels_recover_unavailable",
            "Could not reach enough of the network to read the list",
        ));
    };
    // Plus the ones already known here: held, or carried from an earlier
    // look, and worth another.
    let mut salts: Vec<OwnedRoomSalt> = listed;
    {
        let db = state.db.clone();
        let known = tokio::task::spawn_blocking(move || db.owned_room_salts())
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or_default();
        for salt in known {
            if !salts.contains(&salt) {
                salts.push(salt);
            }
        }
    }
    // A deleted room's records outlive it by weeks, so only the registry says
    // it is gone. Optional: without it, a room is carried rather than put back.
    let url = crate::commands::channels::rendezvous_url(state).await;
    let deleted: Option<HashSet<String>> = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::network::rendezvous::fetch_complete_deleted_channel_ids(&url),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .map(|ids| ids.into_iter().map(|id| id.to_ascii_lowercase()).collect());

    let identity_seed = state.identity.ed25519_secret_key;
    let mut outcome = OwnedRoomScan::default();
    for batch in salts.chunks(PROBE_BATCH) {
        let examined = futures::future::join_all(batch.iter().map(|salt| {
            let deleted = deleted.as_ref();
            async move {
                let seed = channel::derive_owned_room_seed(&identity_seed, salt);
                let ident = ChannelIdentity::from_seed(&seed);
                let slot = examine(state, &ident, deleted).await;
                (*salt, seed, ident, slot)
            }
        }))
        .await;
        for (salt, seed, ident, slot) in examined {
            let id_hex = hex::encode(ident.channel_id);
            let db = state.db.clone();
            match slot {
                // Its salt is kept even if this database lost it, or the list
                // this device publishes would leave the room out.
                Slot::Held(pending) => {
                    let _ =
                        tokio::task::spawn_blocking(move || db.record_channel_owned_salt(&id_hex, &salt))
                            .await;
                    if let Some((epoch, since)) = pending {
                        if resume_waiting_room(state, &ident, epoch, since).await {
                            outcome.unsettled += 1;
                        }
                    }
                }
                Slot::Gone => {
                    let _ = tokio::task::spawn_blocking(move || db.drop_owned_salt(&id_hex)).await;
                }
                Slot::Unsettled => {
                    outcome.unsettled += 1;
                    let _ = tokio::task::spawn_blocking(move || db.carry_owned_salt(&id_hex, &salt))
                        .await;
                }
                Slot::Withheld => {
                    let _ = tokio::task::spawn_blocking(move || db.carry_owned_salt(&id_hex, &salt))
                        .await;
                }
                Slot::Live(snapshot, records) => {
                    match restore_room(state, app, salt, seed, &ident, &snapshot, &records).await {
                        Ok(true) => outcome.recovered += 1,
                        Ok(false) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "could not restore an owned room");
                            outcome.unsettled += 1;
                            let _ = tokio::task::spawn_blocking(move || {
                                db.carry_owned_salt(&id_hex, &salt)
                            })
                            .await;
                        }
                    }
                }
            }
        }
    }
    // The list was read and everything in it is held, carried or gone: this
    // device's list now says at least what the network's did.
    {
        let db = state.db.clone();
        tokio::task::spawn_blocking(move || db.set_owned_rooms_list_synced(true))
            .await
            .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
            .map_err(|e| coded_ctx("channels_recover_failed", "Could not record the list", e))?;
    }
    crate::network::channel_membership::note_owned_rooms_list_read();
    outcome.confirmed = true;
    tracing::info!(
        listed = salts.len(),
        recovered = outcome.recovered,
        unsettled = outcome.unsettled,
        "read the rooms this identity owns"
    );
    if outcome.recovered > 0 {
        if let Some(app) = app {
            let _ = app.emit(
                CHANNELS_RECOVERED_EVENT,
                serde_json::json!({ "count": outcome.recovered }),
            );
        }
    }
    Ok(outcome)
}

/// Look for the rooms this identity owns now, from Settings.
#[tauri::command]
pub async fn recover_owned_channels(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<OwnedRoomScan, String> {
    crate::commands::channels::require_ember(&state).await?;
    scan_owned_rooms(&state, Some(&app)).await
}

/// At startup, once the network has had time to come up: read the identity's
/// list — on every launch of a profile that uses Channels or owns a room, and
/// after a restore — and keep looking at rooms that could not be settled.
/// Until the list is read, this device publishes none of its own.
pub fn spawn_startup_scan(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let due = match app.try_state::<AppState>() {
            Some(state) => {
                let owed = state.db.owned_rooms_list_read_owed().unwrap_or(false);
                let owns = !state.db.owned_room_salts().unwrap_or_default().is_empty();
                let uses_channels =
                    !state.config.read().await.settings.channel_username.trim().is_empty();
                owed || owns || uses_channels
            }
            None => false,
        };
        if due {
            // Long enough for bootstrap to fill the routing table.
            spawn_list_read(app, std::time::Duration::from_secs(45));
        }
    });
}

/// After taking up Channels this session: read the list now, so a room made
/// today is listed today rather than after the next launch.
pub fn ensure_list_read(app: tauri::AppHandle) {
    if !crate::network::channel_membership::owned_rooms_list_read() {
        spawn_list_read(app, std::time::Duration::ZERO);
    }
}

/// Lets the read loop start again however it ends.
struct ReadLoopRunning;

static READ_LOOP_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl Drop for ReadLoopRunning {
    fn drop(&mut self) {
        READ_LOOP_RUNNING.store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Read the list until it has been read — every two minutes for a while if
/// the network cannot be reached well enough yet — and then keep looking at
/// rooms that could not be settled, every few hours. One such loop at a time.
fn spawn_list_read(app: tauri::AppHandle, delay: std::time::Duration) {
    if READ_LOOP_RUNNING.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    let running = ReadLoopRunning;
    tauri::async_runtime::spawn(async move {
        let _running = running;
        tokio::time::sleep(delay).await;
        let mut failures = 0u32;
        loop {
            let Some(state) = app.try_state::<AppState>() else {
                return;
            };
            let wait = match scan_owned_rooms(&state, Some(&app)).await {
                Ok(scan) if scan.unsettled == 0 => return,
                Ok(_) => UNSETTLED_RETRY_SECS,
                Err(e) => {
                    failures += 1;
                    tracing::debug!(failures, error = %e, "owned-room look will retry");
                    if failures >= 24 && crate::network::channel_membership::owned_rooms_list_read() {
                        UNSETTLED_RETRY_SECS
                    } else if failures >= 24 {
                        // Not read at all after this long: keep trying, but
                        // at the slower pace.
                        UNSETTLED_RETRY_SECS / 6
                    } else {
                        120
                    }
                }
            };
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        }
    });
}

/// Mark that the identity's list has to be read again, for a database that
/// came back from a backup or was rebuilt.
pub fn owe_scan(db: &Database) {
    if let Err(e) = db.set_owned_rooms_list_synced(false) {
        tracing::warn!("could not mark the owned-rooms list for a re-read: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ember::crypto::signing_key_from_bytes;

    #[test]
    fn every_list_found_is_merged_and_others_ignored() {
        let identity = signing_key_from_bytes(&[0x21; 32]);
        let pubkey = identity.verifying_key().to_bytes();
        let blob = |salts: &[OwnedRoomSalt], key: &ed25519_dalek::SigningKey| {
            let record = SignedRecord::owned_rooms(salts, key).unwrap();
            [record.data.clone(), record.signature.to_vec()].concat()
        };
        let older = blob(&[[1; 16], [2; 16]], &identity);
        let newer = blob(&[[2; 16], [3; 16]], &identity);
        let stranger = blob(&[[9; 16]], &signing_key_from_bytes(&[0x22; 32]));
        let merged = merged_lists(&[older, newer, stranger.clone(), vec![0u8; 40]], &pubkey).unwrap();
        assert_eq!(merged, vec![[1; 16], [2; 16], [3; 16]]);
        assert_eq!(merged_lists(&[stranger], &pubkey), None, "someone else's list is no list");
        assert_eq!(merged_lists(&[blob(&[], &identity)], &pubkey), Some(Vec::new()));
    }

    /// Records from a walk few nodes answered prove nothing is missing no more
    /// than an empty one does: anyone can file junk under a room's claim key.
    #[test]
    fn only_a_walk_enough_nodes_answered_settles_what_it_lacks() {
        assert!(Probe::Absent.settles_absence());
        assert!(Probe::Found(vec![vec![0u8; 8]], true).settles_absence());
        assert!(!Probe::Found(vec![vec![0u8; 8]], false).settles_absence());
        assert!(!Probe::Unknown.settles_absence());
    }

    #[test]
    fn only_the_room_key_hands_a_room_off_and_only_the_nominee_holds_it_back() {
        use crate::network::ember::dht::publish::ModerationTail;
        let room = ChannelIdentity::generate();
        let nominee = signing_key_from_bytes(&[0x31; 32]);
        let nominee_pk = nominee.verifying_key().to_bytes();
        let stranger = signing_key_from_bytes(&[0x32; 32]);
        let successor = ChannelIdentity::generate();
        let as_blob = |r: SignedRecord| [r.data.clone(), r.signature.to_vec()].concat();

        let claim_by = |key: &ed25519_dalek::SigningKey| {
            as_blob(SignedRecord::channel_succession_claim(
                room.channel_id,
                room.pubkey,
                &successor.pubkey,
                1_900_000_000,
                false,
                key,
            ))
        };
        let snapshot_naming = |nominee: Option<[u8; 32]>| {
            let record = SignedRecord::channel_moderation_at(
                "",
                "",
                &[],
                &[],
                &ModerationTail {
                    owner_pubkey: Some([0x40; 32]),
                    key_epoch: Some(0),
                    successor_nominee: nominee,
                    ..Default::default()
                },
                room.channel_id,
                room.pubkey,
                true,
                &room.signing_key,
                1_900_000_000,
            )
            .unwrap();
            SignedRecord::parse_channel_moderation(&as_blob(record), &room.channel_id).unwrap()
        };
        let named = snapshot_naming(Some(nominee_pk));
        assert!(nominee_claimed(&[claim_by(&nominee)], &room, &named));
        assert!(!nominee_claimed(&[claim_by(&stranger)], &room, &named), "anyone can sign a claim");
        assert!(!nominee_claimed(&[claim_by(&nominee)], &room, &snapshot_naming(None)));
        assert!(!nominee_claimed(&[claim_by(&nominee)], &room, &snapshot_naming(Some([0; 32]))));

        let handoff = SignedRecord::channel_handoff(
            1,
            successor.pubkey,
            room.channel_id,
            room.pubkey,
            false,
            &room.signing_key,
        );
        assert!(handed_off(&[as_blob(handoff)], &room));
        assert!(!handed_off(&[claim_by(&nominee)], &room));
    }
}
