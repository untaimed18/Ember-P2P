//! Rooms their owners have deleted, as this device learns of it.
//!
//! The rendezvous registry keeps a list of deleted rooms, and the list is the
//! server's word: nothing in it proves the owner asked. So the list alone
//! never destroys a room here, or a registry bug or a compromised server could
//! erase every room its users belong to, private ones included. It walks this
//! device out of the room as Leave does, refuses to walk back in, and leaves
//! the room in the list marked as deleted by its owner, where it can be
//! removed. An owner's own rooms are skipped: their deletion is the owner's,
//! through the deleted-elsewhere prompt.
//!
//! What does remove a room is the owner's signed delete, which the registry
//! keeps with the tombstone: signed by the room's own key, so a server cannot
//! make one up. One that checks out against the key this device holds for the
//! room removes it here as the owner's device removed it.
//!
//! The list is read on every Discover walk and on a timer, so a member who
//! never opens Rooms is walked out too, and kept as last read
//! (`Database::note_registry_deleted`), so a registry that cannot be reached
//! does not put a deleted room back.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use crate::app_state::AppState;
use crate::host::{Emitter, Manager};
use crate::network::rendezvous::{delete_proof_valid, DeleteProof};
use crate::network::NetworkCommand;

/// How long the deleted list may take to read before the list as last read
/// stands in for it.
const DELETED_LIST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the signed deletes may take to read.
const PROOFS_TIMEOUT: Duration = Duration::from_secs(30);
/// When the timer first reads the list after Ember starts, and how often after.
const WATCH_FIRST_AFTER: Duration = Duration::from_secs(2 * 60);
const WATCH_EVERY: Duration = Duration::from_secs(6 * 3600);

/// A room this device has just left or removed because its owner deleted it.
#[derive(Debug, Clone, serde::Serialize)]
struct DeletedRoom {
    channel_id: String,
    name: String,
}

fn settling() -> &'static tokio::sync::Mutex<()> {
    static SETTLING: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    SETTLING.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// One look at the signed deletes at a time.
static PROVING: AtomicBool = AtomicBool::new(false);

/// The room's name, whether this device is in it, and whether it owns it.
async fn room_state(state: &AppState, channel_id: &str) -> (String, bool, bool) {
    let db = state.db.clone();
    let id = channel_id.to_string();
    tokio::task::spawn_blocking(move || db.get_channel(&id))
        .await
        .ok()
        .and_then(Result::ok)
        .flatten()
        .map(|row| (row.name, row.in_room, row.is_owner))
        .unwrap_or_default()
}

async fn drop_transfers(state: &AppState, channel_id: &str) {
    if let Ok(id) = <[u8; 16]>::try_from(hex::decode(channel_id).unwrap_or_default().as_slice()) {
        let _ = crate::commands::errors::bounded_send(
            &state.network_tx,
            NetworkCommand::DropChannelTransfers { channel_id: id, member: None },
        )
        .await;
    }
}

fn tell(app: &crate::host::AppHandle, left: Vec<DeletedRoom>, removed: Vec<DeletedRoom>) {
    if left.is_empty() && removed.is_empty() {
        return;
    }
    let _ = app.emit(
        "ember:rooms-deleted",
        serde_json::json!({ "left": left, "removed": removed }),
    );
}

/// Read the registry's deleted rooms and act on them: leave the rooms this
/// device is in, and look for their owners' signed deletes in the background.
/// Returns the deleted ids as read now together with those noted before: a
/// list cut short leaves out rooms an earlier read did name.
pub(crate) async fn settle_deleted_rooms(app: &crate::host::AppHandle, state: &AppState) -> HashSet<String> {
    let _settling = settling().lock().await;
    let url = crate::commands::channels::rendezvous_url(state).await;
    let now = chrono::Utc::now().timestamp();
    let read = tokio::time::timeout(
        DELETED_LIST_TIMEOUT,
        crate::network::rendezvous::fetch_deleted_channel_id_pages(&url),
    )
    .await;
    let fresh: Option<HashSet<String>> = match read {
        Ok(Ok((ids, complete))) => {
            let db = state.db.clone();
            let noted = ids.clone();
            match tokio::task::spawn_blocking(move || db.note_registry_deleted(&noted, complete, now)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(%error, "could not note the registry's deleted rooms"),
                Err(error) => tracing::warn!(%error, "noting the registry's deleted rooms failed"),
            }
            Some(ids.into_iter().map(|id| id.to_ascii_lowercase()).collect())
        }
        Ok(Err(error)) => {
            tracing::warn!(?error, "deleted-room list fetch failed; going by the list as last read");
            None
        }
        Err(_) => {
            tracing::warn!("deleted-room list fetch timed out; going by the list as last read");
            None
        }
    };
    let db = state.db.clone();
    let (noted, inside): (HashSet<String>, Vec<String>) =
        tokio::task::spawn_blocking(move || -> anyhow::Result<(HashSet<String>, Vec<String>)> {
            Ok((db.registry_deleted_ids()?, db.rooms_listed_deleted_in()?))
        })
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let mut left = Vec::new();
    for channel_id in inside {
        let (name, _, _) = room_state(state, &channel_id).await;
        match crate::commands::channels::step_out_of_room(state, &channel_id).await {
            Ok(true) => left.push(DeletedRoom { channel_id, name }),
            Ok(false) => {}
            Err(error) => tracing::warn!(%channel_id, %error, "could not leave a room its owner deleted"),
        }
    }
    tell(app, left, Vec::new());
    let Some(fresh) = fresh else {
        return noted;
    };
    let app = app.clone();
    crate::host::async_runtime::spawn(async move { remove_proved_rooms(app, url).await });
    fresh.into_iter().chain(noted).collect()
}

/// Remove every room held here that the registry lists as deleted and whose
/// owner's signed delete checks out against the room's key.
async fn remove_proved_rooms(app: crate::host::AppHandle, url: String) {
    if PROVING.swap(true, Ordering::AcqRel) {
        return;
    }
    struct Release;
    impl Drop for Release {
        fn drop(&mut self) {
            PROVING.store(false, Ordering::Release);
        }
    }
    let _release = Release;
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let now = chrono::Utc::now().timestamp();
    let db = state.db.clone();
    let awaiting = tokio::task::spawn_blocking(move || db.rooms_awaiting_delete_proof(now))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    if awaiting.is_empty() {
        return;
    }
    let proofs = match tokio::time::timeout(PROOFS_TIMEOUT, crate::network::rendezvous::fetch_delete_proofs(&url)).await
    {
        Ok(Ok(proofs)) => proofs,
        Ok(Err(error)) => {
            tracing::debug!(?error, "could not read the owners' signed deletes");
            return;
        }
        Err(_) => {
            tracing::debug!("reading the owners' signed deletes timed out");
            return;
        }
    };
    let by_room: HashMap<[u8; 16], DeleteProof> = proofs.into_iter().map(|proof| (proof.channel_id, proof)).collect();
    let mut looked = Vec::with_capacity(awaiting.len());
    let mut removed = Vec::new();
    for (channel_id, pubkey) in awaiting {
        looked.push(channel_id.clone());
        let Some(proof) = proved_delete(&by_room, &channel_id, &pubkey) else {
            continue;
        };
        let (name, in_room, is_owner) = room_state(&state, &channel_id).await;
        // Read again here, not only in the query that listed it: a room this
        // device owns is removed through the deleted-elsewhere prompt alone.
        if is_owner {
            continue;
        }
        tracing::info!(channel_id = %channel_id, ts = proof.ts, "removing a room its owner deleted");
        // Out of it first, as a leave goes, should this device still be in:
        // one that already left has said so.
        if in_room {
            if let Err(error) = crate::commands::channels::step_out_of_room(&state, &channel_id).await {
                tracing::warn!(%channel_id, %error, "could not leave a room its owner deleted");
            }
        }
        let db = state.db.clone();
        let id = channel_id.clone();
        match tokio::task::spawn_blocking(move || db.tombstone_channel(&id)).await {
            Ok(Ok(true)) => {
                drop_transfers(&state, &channel_id).await;
                removed.push(DeletedRoom { channel_id, name });
            }
            Ok(Ok(false)) => {}
            Ok(Err(error)) => tracing::warn!(%channel_id, %error, "could not remove a room its owner deleted"),
            Err(error) => tracing::warn!(%channel_id, %error, "removing a room its owner deleted failed"),
        }
    }
    let db = state.db.clone();
    let _ = tokio::task::spawn_blocking(move || db.note_delete_proofs_looked_for(&looked, now)).await;
    tell(&app, Vec::new(), removed);
}

/// The owner's signed delete of the room `channel_id`, if one was served and
/// it checks out against `pubkey`, the room's key as this device holds it.
fn proved_delete<'a>(
    by_room: &'a HashMap<[u8; 16], DeleteProof>,
    channel_id: &str,
    pubkey: &str,
) -> Option<&'a DeleteProof> {
    let mut id = [0u8; 16];
    hex::decode_to_slice(channel_id, &mut id).ok()?;
    let mut key = [0u8; 32];
    hex::decode_to_slice(pubkey, &mut key).ok()?;
    by_room
        .get(&id)
        .filter(|proof| proof.pubkey == key && delete_proof_valid(proof))
}

/// Read the deleted list on a timer too, so a member who never opens Rooms
/// still leaves a room its owner deleted.
pub fn spawn_deleted_rooms_watch(app: crate::host::AppHandle) {
    crate::host::async_runtime::spawn(async move {
        tokio::time::sleep(WATCH_FIRST_AFTER).await;
        loop {
            if let Some(state) = app.try_state::<AppState>() {
                let on = state.config.read().await.settings.ember_native_enabled;
                let db = state.db.clone();
                let holds_rooms = tokio::task::spawn_blocking(move || db.list_channels().map(|rows| !rows.is_empty()))
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or(false);
                if on && holds_rooms {
                    settle_deleted_rooms(&app, &state).await;
                }
            }
            tokio::time::sleep(WATCH_EVERY).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn signed(seed: u8) -> DeleteProof {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pubkey = key.verifying_key().to_bytes();
        let channel_id = crate::network::ember::channel::channel_id_from_pubkey(&pubkey);
        let mut message = Vec::new();
        message.extend_from_slice(b"ember-rdv-v4");
        message.push(0x28);
        message.extend_from_slice(&channel_id);
        message.extend_from_slice(&pubkey);
        message.extend_from_slice(&7i64.to_le_bytes());
        DeleteProof { channel_id, pubkey, ts: 7, sig: key.sign(&message).to_bytes() }
    }

    #[test]
    fn a_room_is_removed_only_for_a_delete_signed_with_the_key_held_for_it() {
        let proof = signed(1);
        let other = signed(2);
        let by_room = HashMap::from([(proof.channel_id, proof.clone()), (other.channel_id, other.clone())]);
        let id = hex::encode(proof.channel_id);
        assert!(proved_delete(&by_room, &id, &hex::encode(proof.pubkey)).is_some());
        // The key this device holds for the room is not the one that signed.
        assert!(proved_delete(&by_room, &id, &hex::encode(other.pubkey)).is_none());
        // No delete served for it.
        assert!(proved_delete(&by_room, &hex::encode([9u8; 16]), &hex::encode(proof.pubkey)).is_none());
        // A delete the server swapped the signature of.
        let forged = HashMap::from([(proof.channel_id, DeleteProof { sig: other.sig, ..proof.clone() })]);
        assert!(proved_delete(&forged, &id, &hex::encode(proof.pubkey)).is_none());
        // Ids as stored are lowercase hex; anything else is not a room.
        assert!(proved_delete(&by_room, "not hex", &hex::encode(proof.pubkey)).is_none());
    }
}
