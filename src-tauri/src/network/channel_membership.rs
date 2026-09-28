//! Channel membership state: presence beacons and rosters, the channel view
//! cache and content keys, moderation, key epochs, and ownership handoff
//! records.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

#[cfg(test)]
mod rendezvous_room_selection_tests {
    use super::select_rendezvous_rooms;
    use crate::network::ember;
    use crate::storage::database::StoredChannel;

    fn room(tag: u8, in_room: bool) -> StoredChannel {
        StoredChannel {
            channel_id: hex::encode([tag; 16]),
            pubkey: String::new(),
            name: String::new(),
            visibility: "public".into(),
            is_owner: false,
            topic: String::new(),
            welcome: String::new(),
            joined_at: 0,
            last_active: 0,
            member_count: 0,
            roster_count: 0,
            unread: 0,
            successor_id: String::new(),
            predecessor_id: String::new(),
            owner_pubkey: String::new(),
            key_epoch: 0,
            successor_nominee: String::new(),
            claim_after_days: 0,
            key_epoch_wanted: 0,
            moderation_updated_at: 0,
            moderation_checked_at: 0,
            in_room,
            deleted: false,
            invites_owner_only: false,
            slow_mode_secs: 0,
            announce_only: false,
            pinned_msg_ids: Vec::new(),
            renamed_at: 0,
            language: String::new(),
        }
    }

    fn ids(rooms: &[&StoredChannel]) -> Vec<String> {
        rooms.iter().map(|ch| ch.channel_id.clone()).collect()
    }

    const MAX: usize = ember::channel::CHANNEL_RENDEZVOUS_MAX_CHANNELS;

    #[test]
    fn a_roster_inside_the_cap_is_taken_whole_and_does_not_rotate() {
        let roster: Vec<StoredChannel> = (0..MAX as u8).map(|i| room(i, true)).collect();
        let first = ids(&select_rendezvous_rooms(&roster, None, 0));
        // Churning registrations beat after beat for a member who already fits
        // would cost POSTs and gain nothing.
        for beat in 0..5 {
            assert_eq!(ids(&select_rendezvous_rooms(&roster, None, beat)), first);
        }
        assert_eq!(first.len(), MAX);
    }

    #[test]
    fn rooms_past_the_cap_are_reached_on_a_later_beat() {
        let roster: Vec<StoredChannel> = (0..(MAX as u8 + 3)).map(|i| room(i, true)).collect();
        let mut seen: Vec<String> = Vec::new();
        for beat in 0..ember::channel::CHANNEL_RENDEZVOUS_ROTATION_DEPTH as u64 {
            for id in ids(&select_rendezvous_rooms(&roster, None, beat)) {
                if !seen.contains(&id) {
                    seen.push(id);
                }
            }
        }
        // The whole point of the rotation: a fifth room used to be registered
        // never, however long the session ran.
        assert!(
            seen.len() > MAX,
            "rotation should reach past one beat's budget, saw {}",
            seen.len()
        );
        for ch in &roster {
            assert!(seen.contains(&ch.channel_id), "{} was never reached", ch.channel_id);
        }
    }

    #[test]
    fn never_registers_more_than_one_beats_budget() {
        let roster: Vec<StoredChannel> = (0..40u8).map(|i| room(i, true)).collect();
        for beat in 0..12 {
            let picked = select_rendezvous_rooms(&roster, None, beat);
            assert!(picked.len() <= MAX, "beat {beat} picked {}", picked.len());
            let unique: std::collections::HashSet<String> = ids(&picked).into_iter().collect();
            assert_eq!(unique.len(), picked.len(), "beat {beat} picked a room twice");
        }
    }

    #[test]
    fn the_focused_room_holds_a_slot_on_every_beat() {
        let roster: Vec<StoredChannel> = (0..20u8).map(|i| room(i, true)).collect();
        let focused = [7u8; 16];
        let focused_hex = hex::encode(focused);
        for beat in 0..12 {
            let picked = ids(&select_rendezvous_rooms(&roster, Some(focused), beat));
            assert_eq!(
                picked.first().map(String::as_str),
                Some(focused_hex.as_str()),
                "beat {beat} dropped the room on screen"
            );
            assert!(picked.len() <= MAX);
            let unique: std::collections::HashSet<&String> = picked.iter().collect();
            assert_eq!(unique.len(), picked.len(), "beat {beat} picked a room twice");
        }
    }

    #[test]
    fn every_rotating_room_is_revisited_before_its_registration_expires() {
        let depth = ember::channel::CHANNEL_RENDEZVOUS_ROTATION_DEPTH as u64;
        let roster: Vec<StoredChannel> = (0..20u8).map(|i| room(i, true)).collect();
        let focused = [7u8; 16];
        for focus in [None, Some(focused)] {
            let windows: Vec<Vec<String>> = (0..24u64)
                .map(|beat| ids(&select_rendezvous_rooms(&roster, focus, beat)))
                .collect();
            let reached: std::collections::HashSet<&String> = windows.iter().flatten().collect();
            // Any room registered once has to come round again within the
            // depth, or its entry lapses between visits.
            for id in reached {
                for start in 0..(windows.len() as u64 - depth) {
                    let seen = (start..start + depth).any(|b| windows[b as usize].contains(id));
                    assert!(seen, "{id} missed beats {start}..{} (focus {focus:?})", start + depth);
                }
            }
        }
    }

    #[test]
    fn a_room_we_have_left_is_never_selected() {
        let mut roster: Vec<StoredChannel> = (0..8u8).map(|i| room(i, true)).collect();
        roster[2].in_room = false;
        roster[5].deleted = true;
        let gone = [roster[2].channel_id.clone(), roster[5].channel_id.clone()];
        for beat in 0..8 {
            for id in ids(&select_rendezvous_rooms(&roster, None, beat)) {
                assert!(!gone.contains(&id), "beat {beat} selected a room we are not in");
            }
        }
    }

    #[test]
    fn focus_on_a_room_we_have_left_does_not_cost_a_slot() {
        let mut roster: Vec<StoredChannel> = (0..8u8).map(|i| room(i, true)).collect();
        roster[3].in_room = false;
        let focused = <[u8; 16]>::try_from(hex::decode(&roster[3].channel_id).unwrap()).unwrap();
        let picked = select_rendezvous_rooms(&roster, Some(focused), 0);
        assert_eq!(picked.len(), MAX);
        assert!(!ids(&picked).contains(&roster[3].channel_id));
    }
}

#[cfg(test)]
mod owner_room_policy_ingest_tests {
    use super::ingest_channel_moderation_records;
    use crate::network::ember::channel::ChannelIdentity;
    use crate::network::ember::dht::publish::{ModerationTail, SignedRecord};
    use crate::storage::database::Database;

    fn blob(ident: &ChannelIdentity, tail: &ModerationTail) -> Vec<u8> {
        blob_at(ident, tail, chrono::Utc::now().timestamp())
    }

    fn blob_at(ident: &ChannelIdentity, tail: &ModerationTail, timestamp: i64) -> Vec<u8> {
        let record = SignedRecord::channel_moderation_at(
            "Topic",
            "Welcome",
            &[],
            &[],
            tail,
            ident.channel_id,
            ident.pubkey,
            false,
            &ident.signing_key,
            timestamp,
        )
        .expect("fits");
        let mut blob = record.data.clone();
        blob.extend_from_slice(&record.signature);
        blob
    }

    fn policy_tail(announce: bool, pins: Vec<[u8; 16]>) -> ModerationTail {
        ModerationTail {
            owner_pubkey: Some([0x77; 32]),
            key_epoch: Some(0),
            successor_nominee: Some([0; 32]),
            claim_after_days: Some(0),
            invites_owner_only: Some(false),
            announce_only: announce.then_some(true),
            pinned_msg_ids: pins,
            ..Default::default()
        }
    }

    /// A member takes the announce flag, the pins and the language from the
    /// owner's newest snapshot only, and a newer one that leaves them out
    /// turns them off.
    #[test]
    fn announce_and_pins_come_only_from_the_newest_snapshot() {
        let path = std::env::temp_dir().join(format!(
            "ember-room-policy-ingest-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        let ident = ChannelIdentity::generate();
        let id_hex = hex::encode(ident.channel_id);
        db.insert_channel(&id_hex, &hex::encode(ident.pubkey), "Lobby", "public", false, None, None)
            .expect("insert channel");

        let pins = vec![[0xA1; 16], [0xA2; 16]];
        let with_language = ModerationTail {
            language: Some("fr"),
            ..policy_tail(true, pins.clone())
        };
        assert!(ingest_channel_moderation_records(
            &db,
            ident.channel_id,
            &[blob(&ident, &with_language)],
        ));
        let row = db.get_channel(&id_hex).unwrap().unwrap();
        assert!(row.announce_only);
        assert_eq!(row.pinned_msg_ids, vec!["a1".repeat(16), "a2".repeat(16)]);
        assert_eq!(row.language, "fr");

        // A snapshot newer than anything a storer can hand back arrives
        // first; the ordinary one after it is older and changes nothing.
        let future = chrono::Utc::now().timestamp() + 3_600;
        assert!(db
            .apply_channel_moderation(
                &id_hex, "Topic", "Welcome", future, &[], &[], None, None, None, None, None,
                None,
            )
            .unwrap());
        assert!(!ingest_channel_moderation_records(
            &db,
            ident.channel_id,
            &[blob(&ident, &policy_tail(false, Vec::new()))],
        ));
        let row = db.get_channel(&id_hex).unwrap().unwrap();
        assert!(row.announce_only, "an older snapshot cannot reopen the room");
        assert_eq!(row.pinned_msg_ids.len(), 2, "or take its pins down");
        assert_eq!(row.language, "fr", "or clear its language");

        // In a second room, the newest snapshot saying nothing is "off".
        // Stamped a second apart: within one second the signature, not
        // arrival order, decides which snapshot is newest.
        let other = ChannelIdentity::generate();
        let other_hex = hex::encode(other.channel_id);
        db.insert_channel(&other_hex, &hex::encode(other.pubkey), "Den", "public", false, None, None)
            .expect("insert channel");
        let stamped = chrono::Utc::now().timestamp();
        assert!(ingest_channel_moderation_records(
            &db,
            other.channel_id,
            &[blob_at(
                &other,
                &ModerationTail {
                    language: Some("de"),
                    ..policy_tail(true, pins)
                },
                stamped,
            )],
        ));
        assert_eq!(db.get_channel(&other_hex).unwrap().unwrap().language, "de");
        assert!(ingest_channel_moderation_records(
            &db,
            other.channel_id,
            &[blob_at(&other, &policy_tail(false, Vec::new()), stamped + 1)],
        ));
        let row = db.get_channel(&other_hex).unwrap().unwrap();
        assert!(!row.announce_only);
        assert!(row.pinned_msg_ids.is_empty());
        assert_eq!(row.language, "", "a newer snapshot without one clears it");

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }
}

#[cfg(test)]
mod channel_roster_snapshot_tests {
    use super::{ChannelRosterSnapshot, CHANNEL_ROSTER_SNAPSHOT_TTL};
    use crate::storage::database::StoredChannelMember;
    use std::time::Instant;

    fn row(pk: u8, last_seen: i64, banned: bool) -> StoredChannelMember {
        StoredChannelMember {
            member_pubkey: hex::encode([pk; 32]),
            nickname: String::new(),
            last_seen,
            banned,
            moderator: false,
        }
    }

    fn snapshot(generation: u64, at: Instant) -> ChannelRosterSnapshot {
        ChannelRosterSnapshot::from_rows(
            vec![row(1, 1_000, false), row(2, 10, false), row(3, 1_000, true)],
            generation,
            at,
        )
    }

    #[test]
    fn status_matches_what_the_table_would_say() {
        let snap = snapshot(0, Instant::now());
        assert_eq!(snap.status(&[1; 32]), Some(false));
        assert_eq!(snap.status(&[3; 32]), Some(true));
        assert_eq!(snap.status(&[9; 32]), None);
    }

    /// Freshness is judged when asked, and a touch still waiting on its flush
    /// counts: otherwise a member heard from a moment ago would read as stale
    /// until the next flush, and a queued line would keep waiting on them.
    #[test]
    fn fresh_members_exclude_bans_and_count_pending_touches() {
        let snap = snapshot(0, Instant::now());
        assert_eq!(snap.fresh_members(500, |_| None), vec![[1; 32]]);
        let fresh = snap.fresh_members(500, |pk| (*pk == [2; 32]).then_some(900));
        assert_eq!(fresh, vec![[1; 32], [2; 32]]);
        let banned_touched = snap.fresh_members(500, |pk| (*pk == [3; 32]).then_some(900));
        assert!(!banned_touched.contains(&[3; 32]), "a ban is not undone by presence");
    }

    #[test]
    fn a_snapshot_is_valid_only_under_its_own_generation() {
        let now = Instant::now();
        let snap = snapshot(7, now);
        assert!(snap.valid_at(7, now));
        assert!(!snap.valid_at(8, now), "any roster write since");
        assert!(!snap.valid_at(7, now + CHANNEL_ROSTER_SNAPSHOT_TTL), "the backstop");
    }

    /// A roster that could not be read admits nobody: every author reads as
    /// banned, nobody is on it for a retired-key check, and it is never taken
    /// as current, so the next caller reads again.
    #[test]
    fn an_unreadable_roster_fails_closed_and_is_never_current() {
        let now = Instant::now();
        let snap = ChannelRosterSnapshot::unreadable(now);
        assert_eq!(snap.status(&[1; 32]), Some(true));
        assert!(snap.fresh_members(0, |_| Some(i64::MAX)).is_empty());
        assert!(!snap.is_moderator(&[1; 32]));
        assert!(!snap.valid_at(0, now));
    }

    #[test]
    fn a_banned_moderator_is_not_a_moderator() {
        let mut moderator = row(6, 1_000, false);
        moderator.moderator = true;
        let mut banned = row(7, 1_000, true);
        banned.moderator = true;
        let snap = ChannelRosterSnapshot::from_rows(vec![moderator, banned], 0, Instant::now());
        assert!(snap.is_moderator(&[6; 32]));
        assert!(!snap.is_moderator(&[7; 32]));
        assert!(!snap.is_moderator(&[8; 32]));
    }

    #[test]
    fn rows_that_do_not_decode_are_dropped() {
        let mut bad = row(4, 1_000, false);
        bad.member_pubkey = "zz".into();
        let snap = ChannelRosterSnapshot::from_rows(vec![bad, row(5, 1_000, false)], 0, Instant::now());
        assert_eq!(snap.fresh_members(0, |_| None), vec![[5; 32]]);
    }
}

#[cfg(test)]
mod channel_view_cache_tests {
    use super::{
        make_room_in_channel_view_cache, CachedChannelView, CHANNEL_VIEW_CACHE_MAX,
        CHANNEL_VIEW_TTL,
    };
    use std::collections::HashMap;
    use std::time::Instant;

    fn view(fetched_at: Instant) -> CachedChannelView {
        CachedChannelView {
            fetched_at,
            row: crate::storage::database::StoredChannel {
                channel_id: String::new(),
                pubkey: String::new(),
                name: String::new(),
                visibility: "public".into(),
                is_owner: false,
                topic: String::new(),
                welcome: String::new(),
                joined_at: 0,
                last_active: 0,
                member_count: 0,
                roster_count: 0,
                unread: 0,
                successor_id: String::new(),
                predecessor_id: String::new(),
                owner_pubkey: String::new(),
                key_epoch: 0,
                successor_nominee: String::new(),
                claim_after_days: 0,
                key_epoch_wanted: 0,
                moderation_updated_at: 0,
                moderation_checked_at: 0,
                in_room: true,
                deleted: false,
                invites_owner_only: false,
                slow_mode_secs: 0,
                announce_only: false,
                pinned_msg_ids: Vec::new(),
                renamed_at: 0,
                language: String::new(),
            },
            content_keys: Vec::new(),
            roster: None,
        }
    }

    fn fill(cache: &mut HashMap<[u8; 16], CachedChannelView>, count: usize, at: Instant) {
        for i in 0..count {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            cache.insert(id, view(at));
        }
    }

    /// Below the bound nothing is touched, however old the entries are: the
    /// per-lookup TTL decides what is *served*, and evicting a stale entry
    /// early would only force the query this cache exists to avoid.
    #[test]
    fn a_cache_under_its_bound_is_left_alone() {
        let now = Instant::now();
        let stale = now - CHANNEL_VIEW_TTL * 10;
        let mut cache = HashMap::new();
        fill(&mut cache, CHANNEL_VIEW_CACHE_MAX - 1, stale);
        make_room_in_channel_view_cache(&mut cache, now);
        assert_eq!(cache.len(), CHANNEL_VIEW_CACHE_MAX - 1);
    }

    /// At the bound, stale entries are what gets reclaimed — the fresh ones
    /// are the rooms currently carrying traffic.
    #[test]
    fn reaching_the_bound_reclaims_the_stale_entries_first() {
        let now = Instant::now();
        let stale = now - CHANNEL_VIEW_TTL * 10;
        let mut cache = HashMap::new();
        fill(&mut cache, CHANNEL_VIEW_CACHE_MAX, stale);
        // One fresh room among them, which must survive.
        let fresh_id = [0xFFu8; 16];
        cache.insert(fresh_id, view(now));

        make_room_in_channel_view_cache(&mut cache, now);

        assert_eq!(cache.len(), 1, "only the fresh room should remain");
        assert!(cache.contains_key(&fresh_id));
    }

    /// A cache that is at its bound and entirely fresh cannot be trimmed by
    /// age, so it is dropped wholesale rather than allowed to grow.
    #[test]
    fn an_all_fresh_cache_at_the_bound_is_dropped_rather_than_grown() {
        let now = Instant::now();
        let mut cache = HashMap::new();
        fill(&mut cache, CHANNEL_VIEW_CACHE_MAX, now);
        make_room_in_channel_view_cache(&mut cache, now);
        assert!(cache.is_empty());
        // Which leaves room for the insert that follows in `cached_channel_view`.
        assert!(cache.len() < CHANNEL_VIEW_CACHE_MAX);
    }
}

/// Re-announce our presence in joined channels so other members can find us.
///
/// Members, not storers, republish presence (presence records are skipped by
/// `take_republish_batch`). Gated to a handful per tick so a large join list
/// cannot stall the network loop.
pub(super) async fn maybe_publish_channel_presence(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
    identity: &crate::storage::identity::NodeIdentity,
) {
    if !settings.ember_native_enabled || db.chat_locked() {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let due = match db.channels_due_for_presence(now, ember::channel::PRESENCE_REPUBLISH_SECS) {
        Ok(ids) => ids,
        Err(e) => {
            debug!("Channel presence scan failed: {e}");
            return;
        }
    };
    let nickname = {
        let name = settings.channel_username.trim();
        if name.is_empty() {
            return;
        }
        name.to_string()
    };
    let refresh_username = !due.is_empty()
        && now.saturating_sub(state.channel_username_refresh_at)
            >= ember::channel::USERNAME_REFRESH_SECS
        && !settings.rendezvous_url.is_empty();
    let signing = ed25519_dalek::SigningKey::from_bytes(&identity.ed25519_secret_key);
    for channel_id_hex in due.into_iter().take(4) {
        let Some(ch) = db.get_channel(&channel_id_hex).ok().flatten() else {
            continue;
        };
        let Ok(id_bytes) = hex::decode(&ch.channel_id) else {
            continue;
        };
        let Ok(pk_bytes) = hex::decode(&ch.pubkey) else {
            continue;
        };
        if id_bytes.len() != 16 || pk_bytes.len() != 32 {
            continue;
        }
        let mut channel_id = [0u8; 16];
        channel_id.copy_from_slice(&id_bytes);
        let mut channel_pubkey = [0u8; 32];
        channel_pubkey.copy_from_slice(&pk_bytes);
        let private = ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE;
        // The current epoch, not the `join_secret` column: a private room's
        // presence extra is sealed with the content key, and publishing it under
        // a retired epoch would leave an evicted member able to enumerate the
        // room's membership while the members who rotated could not read it.
        let Some(join_secret) = current_channel_join_secret(db, &ch) else {
            continue;
        };
        let record = ember::dht::publish::SignedRecord::channel_presence(
            &nickname,
            channel_id,
            channel_pubkey,
            &join_secret,
            private,
            ember::channel::presence_epoch(now),
            &identity.noise_public_key,
            &signing,
        );
        if let Some(publish_id) = state
            .ember_publish
            .start_publish(record, state.ember_dht.routing())
        {
            // Stamped up front so the next scan does not start a second publish
            // for this room while the first is still in flight. Our own
            // last_seen has to move with the announce too: gossip neighbors
            // and the empty-room poll both read `channel_members.last_seen`,
            // and that row was otherwise only written on join — so twenty
            // minutes later we had dropped out of our own roster's "fresh" set
            // while still sitting in the room.
            let _ = db.touch_channel_presence(&channel_id_hex, now);
            let _ = db.upsert_channel_member(
                &channel_id_hex,
                &hex::encode(identity.ed25519_public_key),
                &nickname,
                now,
                Some(&hex::encode(identity.ed25519_public_key)),
            );
            // Handed straight back if the record stored on nobody. The stamp
            // used to be the end of it, so a pass that placed nothing still
            // bought a full republish interval of silence — and since members
            // age out at two intervals, two such passes were enough to make
            // somebody sitting in the room disappear from every roster and
            // stop being picked as a gossip neighbor, with nothing on screen
            // to say why.
            let (tx, rx) = oneshot::channel();
            state.ember_dht_pending_publishes.insert(publish_id, tx);
            let retry_db = db.clone();
            let retry_id = channel_id_hex.clone();
            let retry_at = now - ember::channel::PRESENCE_REPUBLISH_SECS
                + ember::channel::PRESENCE_RETRY_SECS;
            tokio::spawn(async move {
                // A dropped sender means the publish went away without a
                // verdict, which is not evidence it landed either.
                if rx.await.is_ok_and(|result| result.stored_on > 0) {
                    return;
                }
                let _ = retry_db.retry_channel_presence(&retry_id, now, retry_at);
            });
            drive_ember_publish(socket, state, publish_id).await;
        }
    }
    if refresh_username {
        let url = settings.rendezvous_url.clone();
        let pk = identity.ed25519_public_key;
        let sk = identity.ed25519_secret_key;
        let name = nickname.to_lowercase();
        state.channel_username_refresh_at = now;
        tokio::spawn(async move {
            if let Err(error) =
                crate::network::rendezvous::claim_channel_username(&url, &pk, &sk, &name).await
            {
                tracing::debug!(?error, "could not refresh the channel username claim");
            }
        });
    }
}

/// After the loop-owned settings already carry the new Channel username.
///
/// Clearing presence stamps from the Tauri command that saved the name raced
/// the network loop: `maybe_publish_channel_presence` could still be holding
/// the previous handle, consume the newly-due slots, and stamp a ten-minute
/// silence under the old name. Doing it here means the next publish — and this
/// one — reads the username that was just applied.
pub(super) async fn publish_presence_under_new_username(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
    identity: &crate::storage::identity::NodeIdentity,
    old_username: &str,
) {
    let new = settings.channel_username.trim();
    if new.is_empty() || new == old_username.trim() {
        return;
    }
    let pk = hex::encode(identity.ed25519_public_key);
    let _ = db.rename_self_channel_member(&pk, new);
    let _ = db.due_channel_presence_now();
    maybe_publish_channel_presence(socket, state, db, settings, identity).await;
}

/// Publish the tombstones for rooms we have left, and retry the ones that fail.
///
/// Leaving used to be a single fire-and-forget STORE from the Tauri command, so
/// a leave attempted with no route to the storing nodes left us on every other
/// member's roster until we aged out — and nothing noticed or tried again.
///
/// Each attempt mints its own record, which carries a fresh timestamp: a
/// tombstone only removes a member whose `last_seen` is no newer than it, so it
/// has to be newer than the live announcement it replaces. Rejoining clears the
/// marker, which is what stops a late retry deleting the row we just re-earned.
pub(super) async fn publish_channel_departures(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
    identity: &crate::storage::identity::NodeIdentity,
) {
    if !settings.ember_native_enabled || db.chat_locked() {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let Ok(due) = db.channels_due_for_departure(now) else {
        return;
    };
    let nickname = settings.channel_username.trim().to_string();
    let signing = ed25519_dalek::SigningKey::from_bytes(&identity.ed25519_secret_key);
    for channel_id_hex in due.into_iter().take(2) {
        let Some(ch) = db.get_channel(&channel_id_hex).ok().flatten() else {
            let _ = db.clear_channel_departure(&channel_id_hex);
            continue;
        };
        let Ok(cid) = hex::decode(&ch.channel_id)
            .map_err(|_| ())
            .and_then(|b| <[u8; 16]>::try_from(b).map_err(|_| ()))
        else {
            let _ = db.clear_channel_departure(&channel_id_hex);
            continue;
        };
        let Ok(cpk) = hex::decode(&ch.pubkey)
            .map_err(|_| ())
            .and_then(|b| <[u8; 32]>::try_from(b).map_err(|_| ()))
        else {
            let _ = db.clear_channel_departure(&channel_id_hex);
            continue;
        };
        // The epoch the room is on now, not the one we left under: the presence
        // key is derived from it, and members are only looking at the current
        // one.
        let Some(join_secret) = current_channel_join_secret(db, &ch) else {
            let _ = db.clear_channel_departure(&channel_id_hex);
            continue;
        };
        let record = ember::dht::publish::SignedRecord::channel_presence_departure(
            &nickname,
            cid,
            cpk,
            &join_secret,
            ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE,
            ember::channel::presence_epoch(now),
            &identity.noise_public_key,
            &signing,
        );
        // Re-checked against the room's state as it is *now*, not as the list
        // above found it. This loop yields between rooms, so a rejoin can land
        // mid-pass — and a departure published after walking back in tells every
        // member to drop the roster row we just re-earned. The claim also moves
        // the stamp forward, so no second publish starts for this room while
        // this one is in flight.
        let retry_at = now + ember::channel::PRESENCE_RETRY_SECS;
        if !db
            .claim_channel_departure(&channel_id_hex, retry_at)
            .unwrap_or(false)
        {
            continue;
        }
        let Some(publish_id) = state
            .ember_publish
            .start_publish(record, state.ember_dht.routing())
        else {
            continue;
        };
        // Cleared only once a node says it stored the record. Clearing on the
        // attempt is the bug this whole function exists to fix, one layer up.
        let (tx, rx) = oneshot::channel();
        state.ember_dht_pending_publishes.insert(publish_id, tx);
        let retry_db = db.clone();
        let retry_id = channel_id_hex.clone();
        tokio::spawn(async move {
            if rx.await.is_ok_and(|result| result.stored_on > 0) {
                let _ = retry_db.clear_channel_departure(&retry_id);
            }
        });
        drive_ember_publish(socket, state, publish_id).await;
    }
}

/// A room's identity and reading keys, as the packet paths need them.
#[derive(Clone)]
pub(super) struct CachedChannelView {
    pub(super) fetched_at: std::time::Instant,
    pub(super) row: crate::storage::database::StoredChannel,
    pub(super) content_keys: Vec<[u8; 32]>,
    /// Carried across refreshes of `row`: it has its own validity rule (see
    /// [`ChannelRosterSnapshot`]), and the view's one-second TTL would
    /// otherwise throw it away with the row.
    pub(super) roster: Option<Arc<ChannelRosterSnapshot>>,
}

/// One room's `channel_members`, as of a [`Database::channel_roster_generation`].
///
/// Every roster write moves the generation, so a snapshot whose generation
/// still matches is exactly what the table holds — including bans written from
/// an IPC command, which never pass through the network loop. That is what
/// lets the per-frame paths (fanout, relay, presence, chat ingest) answer
/// "who is here" and "is this author banned" without a query each, where each
/// used to be a full `list_channel_members` scan or a point read on the
/// process-wide connection, run inline on the `select!` loop.
///
/// Freshness is judged at read time, against `now` and the buffered
/// [`NetworkState::channel_member_touches`], so a snapshot does not go stale
/// just because time passed or a touch is still waiting on its flush.
pub(super) struct ChannelRosterSnapshot {
    fetched_at: std::time::Instant,
    generation: u64,
    /// In `list_channel_members` order, which is the order
    /// [`channel_member_pubkeys`] has always returned.
    rows: Vec<RosterRow>,
    index: HashMap<[u8; 32], usize>,
    /// The roster could not be read. Every question is answered in the
    /// direction that admits nobody: all banned, none fresh, no moderators.
    unreadable: bool,
}

struct RosterRow {
    member: [u8; 32],
    last_seen: i64,
    banned: bool,
    moderator: bool,
}

/// Backstop only: invalidation is by generation. Bounds how long a write
/// outside `Database`'s methods — there are none today — could go unseen.
pub(super) const CHANNEL_ROSTER_SNAPSHOT_TTL: std::time::Duration = std::time::Duration::from_secs(
    crate::storage::database::CHANNEL_ROSTER_SNAPSHOT_TTL_SECS as u64,
);

impl ChannelRosterSnapshot {
    pub(super) fn from_rows(
        rows: Vec<crate::storage::database::StoredChannelMember>,
        generation: u64,
        fetched_at: std::time::Instant,
    ) -> Self {
        let rows: Vec<RosterRow> = rows
            .into_iter()
            .filter_map(|row| {
                let bytes = hex::decode(&row.member_pubkey).ok()?;
                Some(RosterRow {
                    member: <[u8; 32]>::try_from(bytes).ok()?,
                    last_seen: row.last_seen,
                    banned: row.banned,
                    moderator: row.moderator,
                })
            })
            .collect();
        let index = rows
            .iter()
            .enumerate()
            .map(|(i, row)| (row.member, i))
            .collect();
        Self {
            fetched_at,
            generation,
            rows,
            index,
            unreadable: false,
        }
    }

    pub(super) fn unreadable(fetched_at: std::time::Instant) -> Self {
        Self {
            fetched_at,
            generation: 0,
            rows: Vec::new(),
            index: HashMap::new(),
            unreadable: true,
        }
    }

    pub(super) fn valid_at(&self, generation: u64, now: std::time::Instant) -> bool {
        !self.unreadable
            && self.generation == generation
            && now.saturating_duration_since(self.fetched_at) < CHANNEL_ROSTER_SNAPSHOT_TTL
    }

    /// Same answer as [`Database::channel_member_status`]: `None` for no row,
    /// `Some(banned)` otherwise.
    pub(super) fn status(&self, member: &[u8; 32]) -> Option<bool> {
        if self.unreadable {
            return Some(true);
        }
        self.index.get(member).map(|&i| self.rows[i].banned)
    }

    pub(super) fn is_moderator(&self, member: &[u8; 32]) -> bool {
        self.index
            .get(member)
            .is_some_and(|&i| self.rows[i].moderator && !self.rows[i].banned)
    }

    /// Same answer as [`channel_member_pubkeys`], with each row's `last_seen`
    /// raised by whatever `pending` still holds for it.
    pub(super) fn fresh_members(
        &self,
        cutoff: i64,
        pending: impl Fn(&[u8; 32]) -> Option<i64>,
    ) -> Vec<[u8; 32]> {
        self.rows
            .iter()
            .filter(|row| {
                !row.banned && row.last_seen.max(pending(&row.member).unwrap_or(i64::MIN)) >= cutoff
            })
            .map(|row| row.member)
            .collect()
    }
}

/// The room's roster snapshot, re-read only when the table has moved since.
///
/// Held on the room's [`CachedChannelView`], so a room this device has not
/// joined caches nothing here either. For such a room this still answers,
/// from a fresh read.
pub(super) fn channel_roster_snapshot(
    state: &mut NetworkState,
    db: &Database,
    channel_id: [u8; 16],
) -> Arc<ChannelRosterSnapshot> {
    let now = std::time::Instant::now();
    let channel_id_hex = hex::encode(channel_id);
    let generation = db.channel_roster_generation(&channel_id_hex);
    if let Some(snapshot) = state
        .channel_view_cache
        .get(&channel_id)
        .and_then(|view| view.roster.as_ref())
    {
        if snapshot.valid_at(generation, now) {
            return snapshot.clone();
        }
    }
    // Not cached, so the next caller reads again. Cached as an empty roster, a
    // transient error was a room where nobody was banned for the next 30 s.
    let rows = match db.list_channel_members(&channel_id_hex) {
        Ok(rows) => rows,
        Err(e) => {
            debug!("Channel roster read failed for {channel_id_hex}: {e}");
            return Arc::new(ChannelRosterSnapshot::unreadable(now));
        }
    };
    let snapshot = Arc::new(ChannelRosterSnapshot::from_rows(rows, generation, now));
    if let Some(view) = state.channel_view_cache.get_mut(&channel_id) {
        view.roster = Some(snapshot.clone());
    }
    snapshot
}

/// [`channel_member_pubkeys`] from the room's roster snapshot.
pub(super) fn channel_member_pubkeys_cached(
    state: &mut NetworkState,
    db: &Database,
    channel_id: [u8; 16],
) -> Vec<[u8; 32]> {
    let snapshot = channel_roster_snapshot(state, db, channel_id);
    let cutoff = chrono::Utc::now()
        .timestamp()
        .saturating_sub(ember::channel::PRESENCE_FRESH_SECS);
    let touches = &state.channel_member_touches;
    snapshot.fresh_members(cutoff, |pk| touches.get(&(channel_id, *pk)).copied())
}

/// [`Database::channel_member_status`] from the room's roster snapshot.
pub(super) fn channel_member_status_cached(
    state: &mut NetworkState,
    db: &Database,
    channel_id: [u8; 16],
    member: &[u8; 32],
) -> Option<bool> {
    channel_roster_snapshot(state, db, channel_id).status(member)
}

/// How long a memoised room view is served before it is read again.
///
/// Deliberately short. The alternative — invalidating on every write to
/// `channels` — is self-defeating here, because storing a received message
/// updates `last_active` on the very path this cache exists to keep out of
/// the database.
///
/// Every consequence of a window this size is self-correcting, which is what
/// makes a time bound the right instrument:
/// - A room left moments ago ingests up to a second more of its own traffic.
/// - A key epoch that rotated moments ago fails the AEAD, which is already an
///   expected outcome here (`channel_content_keys` returns a *window* of
///   epochs precisely because in-flight frames are sealed under older ones).
///   The frame is dropped and forgotten, so the sender's retry and history
///   sync both still deliver it.
///
/// None of it stands in for an authorization check: transfer frames are
/// authenticated to the pair under `derive_xfer_key`, and bans are re-read
/// from the database where they are enforced.
pub(super) const CHANNEL_VIEW_TTL: std::time::Duration = std::time::Duration::from_secs(1);

/// Rooms held in [`NetworkState::channel_view_cache`].
///
/// Joining is deliberately uncapped, so this has to sit well clear of any
/// plausible join list rather than at the cap of something else: past it the
/// map is dropped and every room pays its query again, which is the behaviour
/// this cache exists to remove. An entry is on the order of a kilobyte.
pub(super) const CHANNEL_VIEW_CACHE_MAX: usize = 256;

/// Room row and content keys for a packet path, from cache when fresh.
///
/// Every distinct inbound channel frame used to pay `get_channel` — a query
/// carrying two correlated `COUNT(*)` subqueries — plus, for a private room,
/// `load_channel_key_epochs` and `load_channel_join_secret`. The dedup gate
/// upstream makes retransmits free, but Ember Transfer blocks each carry a
/// unique `msg_id`, so one person receiving room attachments drove hundreds of
/// these a second, each taking the process's single SQLite connection on the
/// network task and blocking every IPC handler's blocking-pool query behind it.
pub(super) fn cached_channel_view(
    state: &mut NetworkState,
    db: &Database,
    channel_id: [u8; 16],
) -> Option<CachedChannelView> {
    let now = std::time::Instant::now();
    if let Some(hit) = state.channel_view_cache.get(&channel_id) {
        if now.saturating_duration_since(hit.fetched_at) < CHANNEL_VIEW_TTL {
            return Some(hit.clone());
        }
    }
    let channel_id_hex = hex::encode(channel_id);
    // A miss caches nothing: a frame for a room this device has not joined is
    // exactly what an attacker can send an unbounded number of, and caching
    // absence would let them size this map.
    let row = db.get_channel_lite(&channel_id_hex).ok().flatten()?;
    let content_keys = channel_content_keys(db, &row);
    let roster = state
        .channel_view_cache
        .get(&channel_id)
        .and_then(|old| old.roster.clone());
    let view = CachedChannelView {
        fetched_at: now,
        row,
        content_keys,
        roster,
    };
    make_room_in_channel_view_cache(&mut state.channel_view_cache, now);
    state.channel_view_cache.insert(channel_id, view.clone());
    Some(view)
}

/// Keep [`NetworkState::channel_view_cache`] under its bound before an insert.
///
/// Split from [`cached_channel_view`] so the bound can be tested without a
/// `NetworkState`, which has no constructor outside `start_network`.
///
/// Stale entries go first; only if that frees nothing does the whole map go.
/// Dropping everything is the deliberately blunt fallback — past the bound
/// every room pays its query again, which is what this cache exists to stop,
/// so the bound is set well clear of any plausible join list rather than at
/// the cap of something else.
pub(super) fn make_room_in_channel_view_cache(
    cache: &mut HashMap<[u8; 16], CachedChannelView>,
    now: std::time::Instant,
) {
    if cache.len() < CHANNEL_VIEW_CACHE_MAX {
        return;
    }
    cache.retain(|_, v| now.saturating_duration_since(v.fetched_at) < CHANNEL_VIEW_TTL);
    if cache.len() >= CHANNEL_VIEW_CACHE_MAX {
        cache.clear();
    }
}

/// Content keys this room can be read with, newest epoch first.
///
/// Private rooms rotate on a ban, so anything already in flight — a relayed
/// message, a history-sync reply, an attachment sealed on disk before the
/// rotation — is still sealed under an older epoch. Readers try these in
/// order; an AEAD failure is a clean signal, and the retained window is small.
///
/// Public rooms have exactly one key, derived from the channel pubkey that
/// anyone can compute, so rotating one would evict nobody.
pub(super) fn channel_content_keys(
    db: &Database,
    ch: &crate::storage::database::StoredChannel,
) -> Vec<[u8; 32]> {
    if ch.visibility != ember::channel::CHANNEL_KIND_PRIVATE {
        let Some(pk) = hex::decode(&ch.pubkey)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            return Vec::new();
        };
        return vec![ember::channel::content_key(
            &ember::channel::public_join_secret(&pk),
        )];
    }
    let mut keys: Vec<[u8; 32]> = db
        .load_channel_key_epochs(&ch.channel_id)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, secret)| ember::channel::content_key(&secret))
        .collect();
    // Epoch 0 is the secret the invite was minted with, still in `join_secret`
    // for any room that has never rotated.
    if let Ok(Some(secret)) = db.load_channel_join_secret(&ch.channel_id) {
        let legacy = ember::channel::content_key(&secret);
        if !keys.contains(&legacy) {
            keys.push(legacy);
        }
    }
    keys
}

/// The join secret this room seals *new* traffic with: its newest epoch, or the
/// original invite secret for a room that has never rotated.
///
/// Distinct from [`channel_content_keys`] because presence takes the secret
/// itself rather than the derived content key.
pub(super) fn current_channel_join_secret(
    db: &Database,
    ch: &crate::storage::database::StoredChannel,
) -> Option<[u8; 32]> {
    if ch.visibility != ember::channel::CHANNEL_KIND_PRIVATE {
        return hex::decode(&ch.pubkey)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(|pk| ember::channel::public_join_secret(&pk));
    }
    if let Some((_, secret)) = db
        .load_channel_key_epochs(&ch.channel_id)
        .unwrap_or_default()
        .into_iter()
        .next()
    {
        return Some(secret);
    }
    db.load_channel_join_secret(&ch.channel_id).ok().flatten()
}

/// The key this room seals *new* traffic with.
pub(super) fn channel_content_key(
    db: &Database,
    ch: &crate::storage::database::StoredChannel,
) -> Option<[u8; 32]> {
    channel_content_keys(db, ch).into_iter().next()
}

pub(super) fn channel_member_pubkeys(
    db: &Database,
    channel_id_hex: &str,
) -> Vec<[u8; 32]> {
    let Ok(rows) = db.list_channel_members(channel_id_hex) else {
        return Vec::new();
    };
    let now = chrono::Utc::now().timestamp();
    let cutoff = now.saturating_sub(ember::channel::PRESENCE_FRESH_SECS);
    rows.into_iter()
        .filter_map(|row| {
            if row.banned {
                return None;
            }
            if row.last_seen < cutoff {
                return None;
            }
            let bytes = hex::decode(row.member_pubkey).ok()?;
            <[u8; 32]>::try_from(bytes).ok()
        })
        .collect()
}

/// Ceiling on [`NetworkState::channel_member_touches`] between flushes.
///
/// Rooms joined times the roster cap. The buffer is keyed by
/// `(room, member)` and keeps only the newest timestamp per key, so its size
/// tracks how many distinct members have been heard from rather than how many
/// datagrams arrived — which is why the flush interval does not enter into it.
pub(super) const MAX_CHANNEL_MEMBER_TOUCHES: usize = 4096;

/// Queue a roster row for the next presence emit.
///
/// Bounded by the same roster cap as the table it mirrors, so a peer spraying
/// beacons for identities we refuse to admit cannot grow this instead.
pub(super) fn mark_channel_presence_dirty(
    state: &mut NetworkState,
    channel_id: [u8; 16],
    member: &[u8; 32],
    at: i64,
) {
    let room = state.channel_presence_dirty.entry(channel_id).or_default();
    if room.len() >= ember::channel::CHANNEL_MEMBERS_MAX && !room.contains_key(member) {
        return;
    }
    let slot = room.entry(*member).or_insert(at);
    *slot = (*slot).max(at);
}

/// Record that a member was demonstrably alive a moment ago.
///
/// Every caller has already established the author cryptographically — a
/// signature over the frame, or the pairwise transfer key that only that member
/// and this device can derive — so this is first-hand evidence rather than one
/// peer's claim about another. It is also free: these frames were already
/// crossing the mesh between exactly these members, and the one thing they
/// proved was the one thing the roster never learned from them. A member who
/// was relaying gossip and moving a file could still be shown offline.
///
/// Deliberately a touch and never an insert. Whether a stranger may *join* a
/// roster is a separate question that public and private rooms answer
/// differently — see [`ember::channel::chat_author_joins_gossip_roster`] — and
/// answering it here would quietly route around it.
/// Buffered rather than written, and flushed on an interval by
/// [`flush_channel_member_touches`]. This is called for *every* channel
/// datagram that authenticates, and the write it used to do was a synchronous
/// autocommitted `UPDATE` on the network task — one transaction, and under
/// `synchronous=FULL` one fsync, per datagram, each taking the connection
/// mutex that every other database user in the process shares. A member in a
/// few busy rooms turned that into tens of fsyncs a second on the reactor.
///
/// Only the newest timestamp per member survives, which is all the row can
/// hold anyway: the `UPDATE` moves `last_seen` forward or does nothing, so
/// collapsing a second's worth of datagrams into one write loses nothing.
pub(super) fn note_channel_member_alive(
    state: &mut NetworkState,
    channel_id: [u8; 16],
    member: &[u8; 32],
    at: i64,
) {
    if *member == state.local_ed25519_pubkey {
        return;
    }
    if at <= 0 {
        return;
    }
    // Bounded like the roster it mirrors. Every caller has already
    // authenticated the author against a room we are in, so the key space is
    // rooms x members, but a cap keeps a burst from deciding how large this
    // grows between flushes.
    if state.channel_member_touches.len() >= MAX_CHANNEL_MEMBER_TOUCHES
        && !state
            .channel_member_touches
            .contains_key(&(channel_id, *member))
    {
        return;
    }
    let slot = state
        .channel_member_touches
        .entry((channel_id, *member))
        .or_insert(at);
    *slot = (*slot).max(at);
}

/// Write the buffered `last_seen` touches as one transaction, and queue a
/// presence delta for each row that actually moved.
///
/// Runs immediately before [`emit_channel_presence_deltas`], so a member whose
/// row moved on this flush is reported on this tick rather than the next.
/// Presence therefore resolves at [`CHANNEL_MEMBER_TOUCH_FLUSH_INTERVAL`]
/// granularity, not the caller's 1 Hz — which is the point, and is well inside
/// what a "last seen" column conveys.
pub(super) fn flush_channel_member_touches(state: &mut NetworkState, db: &Database) {
    if state.channel_member_touches.is_empty() {
        return;
    }
    // Paced, because the write commits a transaction and the database is
    // opened `PRAGMA synchronous=FULL` — so each flush forces an fsync, on the
    // Tokio worker running the network `select!`. At the caller's 1 Hz that is
    // 86,400 fsyncs a day, each stalling all UDP/TCP servicing for as long as
    // the disk takes (tens of milliseconds on a spinning or encrypted volume).
    // `last_seen` is soft state that the member's next datagram re-establishes,
    // and the buffer coalesces in the meantime, so batching costs only a little
    // resolution on a presence timestamp.
    //
    // The pacing yields to the buffer's own ceiling. `note_channel_member_alive`
    // refuses a *new* key once the map is full, so a window long enough to
    // reach `MAX_CHANNEL_MEMBER_TOUCHES` distinct `(room, member)` pairs starts
    // silently dropping members' presence instead of merely delaying it — and
    // the cap is roughly sixteen full rosters, which a user in that many busy
    // rooms can reach in ten seconds where they could not in one. Draining at
    // the halfway mark keeps the cap from ever being the thing that loses a
    // touch, while leaving the common case on the slow cadence.
    let near_capacity = state.channel_member_touches.len() >= MAX_CHANNEL_MEMBER_TOUCHES / 2;
    if !near_capacity
        && state
            .channel_member_touch_flushed_at
            .is_some_and(|at| at.elapsed() < CHANNEL_MEMBER_TOUCH_FLUSH_INTERVAL)
    {
        return;
    }
    state.channel_member_touch_flushed_at = Some(std::time::Instant::now());
    let pending: Vec<(([u8; 16], [u8; 32]), i64)> =
        state.channel_member_touches.drain().collect();
    let rows: Vec<(String, String, i64)> = pending
        .iter()
        .map(|((channel_id, member), at)| (hex::encode(channel_id), hex::encode(member), *at))
        .collect();
    let updated = match db.touch_channel_members_last_seen(&rows) {
        Ok(updated) => updated,
        Err(e) => {
            // Dropped rather than retried: each of these is "this member was
            // alive a moment ago", and the next datagram from them re-queues a
            // fresher one. Holding them would only age the buffer.
            debug!("Failed to flush channel member presence touches: {e}");
            return;
        }
    };
    for (((channel_id, member), at), moved) in pending.into_iter().zip(updated) {
        if moved {
            mark_channel_presence_dirty(state, channel_id, &member, at);
        }
    }
}

/// Push the roster rows whose `last_seen` moved since the last pass.
///
/// A delta rather than a nudge to re-read the whole list. `ember:channel-members`
/// means "the roster changed shape" and costs the UI a round trip through
/// `list_channel_members` for every member of the room; presence moves far more
/// often than membership does, and firing that event every time somebody was
/// heard from turned a quiet room into a steady stream of full refetches. What
/// changed here is one number on one row, so that is what goes across.
pub(super) fn emit_channel_presence_deltas(state: &mut NetworkState, app_handle: &tauri::AppHandle) {
    if state.channel_presence_dirty.is_empty() {
        return;
    }
    for (channel_id, rows) in std::mem::take(&mut state.channel_presence_dirty) {
        if rows.is_empty() {
            continue;
        }
        let members: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|(member, last_seen)| {
                serde_json::json!({
                    "member_pubkey": hex::encode(member),
                    "last_seen": last_seen,
                })
            })
            .collect();
        let _ = app_handle.emit(
            "ember:channel-presence",
            serde_json::json!({
                "channel_id": hex::encode(channel_id),
                "members": members,
            }),
        );
    }
}

/// Rooms beaten per one-second tick.
///
/// One, because a beat is [`ember::channel::CHANNEL_NEIGHBOR_COUNT`] unicasts
/// and those are charged to the same relay allowance as the mesh's own
/// forwarding — `channel_gossip_rate_ok`. Beating several rooms in one tick
/// would spend the whole second's budget on presence and have the rest of it
/// silently shed, including part of the digest that prompted it. At a
/// [`ember::channel::PRESENCE_BEAT_SECS`] interval this still covers far more
/// rooms than anyone joins, and `a_beat_fits_the_relay_allowance_for_a_second`
/// pins the relationship.
pub(super) const CHANNEL_BEACON_BEAT_PER_TICK: usize = 1;

/// Keep a beacon for later relay.
///
/// The roster cap and its eviction rules are what stop a flood of invented
/// identities being chosen as gossip neighbors. A separate beacon map that
/// accepted anyone would be a way around that, so callers hand in only beacons
/// the table admitted — `apply_channel_presence_beacons` skips a
/// [`ChannelMemberWrite::Refused`] — and the size cap here is a backstop for
/// the tombstones, which are kept for identities the roster no longer holds.
pub(super) fn remember_channel_beacon(
    state: &mut NetworkState,
    channel_id: [u8; 16],
    beacon: ember::channel::PresenceBeacon,
) {
    let room = state.channel_beacons.entry(channel_id).or_default();
    if room.len() >= ember::channel::CHANNEL_MEMBERS_MAX && !room.contains_key(&beacon.member) {
        return;
    }
    ember::channel::keep_latest_beacon(room, beacon);
}

/// The beacons worth putting in one digest frame, freshest first.
///
/// Newest-first is what makes the layer converge on the case people notice.
/// A member who just arrived is by definition the freshest beacon in the room,
/// so they ride out to every neighbor on the next round and reach the far side
/// in a few hops, while a member who has been sitting there for an hour is
/// already known to everyone and can afford to wait.
pub(super) fn channel_presence_digest(
    state: &mut NetworkState,
    channel_id: [u8; 16],
    ours: ember::channel::PresenceBeacon,
    now: i64,
) -> Vec<ember::channel::PresenceBeacon> {
    let mut out = vec![ours];
    let Some(room) = state.channel_beacons.get_mut(&channel_id) else {
        return out;
    };
    // A beacon past the freshness window says nothing anyone can act on: its
    // subject is offline by every rule that reads it. Dropped rather than
    // merely sorted last, because in a room with fewer members than a digest
    // holds nothing ever sorts it out — a member who left months ago would ride
    // every digest this device sent for as long as it stayed in the room.
    let cutoff = now.saturating_sub(ember::channel::PRESENCE_FRESH_SECS);
    room.retain(|_, beacon| beacon.timestamp >= cutoff);
    if room.is_empty() {
        state.channel_beacons.remove(&channel_id);
        return out;
    }
    let mut others: Vec<ember::channel::PresenceBeacon> = room
        .values()
        .filter(|b| b.member != ours.member)
        .copied()
        .collect();
    others.sort_unstable_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then_with(|| a.member.cmp(&b.member))
    });
    out.extend(
        others
            .into_iter()
            .take(ember::channel::PRESENCE_BEACON_PROVEN_BATCH_MAX - 1),
    );
    out
}

/// Seal a beacon batch for one room.
pub(super) fn seal_channel_beacons(
    channel_id: [u8; 16],
    key: &[u8; 32],
    beacons: &[ember::channel::PresenceBeacon],
    ttl: u8,
    now: i64,
) -> Vec<u8> {
    let plain = ember::channel::encode_channel_presence_beacons(beacons);
    let mut envelope_id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut envelope_id);
    ember::channel::ChannelGossip::sealed(
        channel_id,
        envelope_id,
        key,
        now.max(0) as u64,
        &plain,
        ttl,
        now,
    )
    .encode()
}

/// Announce ourselves on the live mesh and pass along the freshest beacons we
/// hold while we are at it.
///
/// Sent at `ttl = 1`, which is what separates the two ways a beacon travels.
/// A digest is anti-entropy: one hop to our own neighbors, repeated on a timer,
/// so its cost is one small frame per neighbor per beat no matter how large the
/// room. Flooding it instead would multiply by the roster — in a full room that
/// is a quarter of a million frames a minute for something nobody is waiting
/// on. Joins and leaves are the frames people *are* waiting on, and those flood
/// (see [`flood_channel_presence_beacon`]); they are rare enough to afford it.
pub(super) async fn maybe_beat_channel_presence(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
) {
    if !settings.ember_native_enabled || db.chat_locked() {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let Some(channels) = channels_lite_cached(state, db) else {
        return;
    };
    let mut beaten = 0usize;
    for ch in channels.iter() {
        if beaten >= CHANNEL_BEACON_BEAT_PER_TICK {
            break;
        }
        if !ch.in_room_now() {
            continue;
        }
        let Ok(id_bytes) = hex::decode(&ch.channel_id) else {
            continue;
        };
        let Ok(channel_id) = <[u8; 16]>::try_from(id_bytes) else {
            continue;
        };
        let last = state
            .channel_beacon_beat_at
            .get(&channel_id)
            .copied()
            .unwrap_or(0);
        if !ember::channel::schedule_due(last, now, ember::channel::PRESENCE_BEAT_SECS) {
            continue;
        }
        // Stamped before the work rather than after it. A room that cannot beat
        // — no content key on this device, nobody on the roster to beat at —
        // has to back off like any other, or every tick re-reads its key and
        // its whole member list to reach the same conclusion a second later.
        state.channel_beacon_beat_at.insert(channel_id, now);
        let Some(key) = channel_content_key(db, ch) else {
            continue;
        };
        let neighbors = ember::channel::gossip_neighbors(
            &state.local_ed25519_pubkey,
            &channel_member_pubkeys(db, &ch.channel_id),
            ember::channel::CHANNEL_NEIGHBOR_COUNT,
        );
        if neighbors.is_empty() {
            continue;
        }
        let ours = ember::channel::sign_presence_beacon(
            &ember::crypto::signing_key_from_bytes(&state.local_ed25519_seed),
            &state.local_ed25519_pubkey,
            &channel_id,
            ch.key_epoch,
            now,
            false,
        )
        .with_key_proof(&channel_id, &key);
        remember_channel_beacon(state, channel_id, ours);
        let digest = channel_presence_digest(state, channel_id, ours, now);
        let body = seal_channel_beacons(channel_id, &key, &digest, 1, now);
        for peer in neighbors {
            send_channel_gossip_unicast(socket, state, db, channel_id, peer, body.clone()).await;
        }
        beaten += 1;
    }
}

/// Flood a single beacon to the room, for the moments presence actually
/// changes: arriving, and leaving.
///
/// These are the events a person is watching for, and the only ones worth
/// `members × degree` sends. Everything else rides the periodic digest.
pub(super) async fn flood_channel_presence_beacon(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    channel_id: [u8; 16],
    departed: bool,
    now: i64,
) {
    let channel_id_hex = hex::encode(channel_id);
    let Ok(Some(ch)) = db.get_channel(&channel_id_hex) else {
        return;
    };
    let Some(key) = channel_content_key(db, &ch) else {
        return;
    };
    let ours = ember::channel::sign_presence_beacon(
        &ember::crypto::signing_key_from_bytes(&state.local_ed25519_seed),
        &state.local_ed25519_pubkey,
        &channel_id,
        ch.key_epoch,
        now,
        departed,
    )
    .with_key_proof(&channel_id, &key);
    let body = seal_channel_beacons(
        channel_id,
        &key,
        &[ours],
        ember::channel::CHANNEL_MSG_TTL_DEFAULT,
        now,
    );
    if departed {
        // Nothing local to keep: the room is being left, so its schedules and
        // caches go with it rather than sitting there holding a tombstone we
        // would go on republishing to ourselves.
        state.channel_beacons.remove(&channel_id);
        state.channel_beacon_beat_at.remove(&channel_id);
        state.channel_beacon_inserts.remove(&channel_id);
        state.channel_presence_dirty.remove(&channel_id);
        state
            .channel_beacon_flood_at
            .retain(|(room, _), _| *room != channel_id);
        // Only when it is the room we were watching. Leaving one room while
        // reading another must not drop the other back to the resting walk.
        if state.channel_focused == Some(channel_id) {
            state.channel_focused = None;
        }
    } else {
        remember_channel_beacon(state, channel_id, ours);
        state.channel_beacon_beat_at.insert(channel_id, now);
    }
    // Handed to our neighbors directly rather than through
    // `fanout_channel_gossip_body`, which refuses to send for a room this
    // device is not in — and a leave is by definition sent from outside it,
    // since `leave_channel` clears `in_room` before the network loop ever sees
    // the command. The frame still carries a full TTL, so the neighbors that
    // take it are the ones that flood it onward.
    let neighbors = ember::channel::gossip_neighbors(
        &state.local_ed25519_pubkey,
        &channel_member_pubkeys(db, &channel_id_hex),
        ember::channel::CHANNEL_NEIGHBOR_COUNT,
    );
    for peer in neighbors {
        send_channel_gossip_unicast(socket, state, db, channel_id, peer, body.clone()).await;
    }
}

pub(super) fn channel_beacon_flood_ok(
    state: &mut NetworkState,
    channel_id: [u8; 16],
    member: &[u8; 32],
    now: i64,
) -> bool {
    let key = (channel_id, *member);
    let last = state.channel_beacon_flood_at.get(&key).copied().unwrap_or(0);
    if !ember::channel::beacon_flood_allow(last, now) {
        return false;
    }
    if state.channel_beacon_flood_at.len() >= ember::channel::CHANNEL_MEMBERS_MAX * 4 {
        state
            .channel_beacon_flood_at
            .retain(|_, at| now.saturating_sub(*at) < ember::channel::PRESENCE_FRESH_SECS);
    }
    state.channel_beacon_flood_at.insert(key, now);
    true
}

pub(super) fn channel_beacon_insert_ok(
    state: &mut NetworkState,
    channel_id: [u8; 16],
    now: i64,
) -> bool {
    let slot = state
        .channel_beacon_inserts
        .entry(channel_id)
        .or_insert((now, 0));
    ember::channel::beacon_insert_allow(slot, now)
}

/// Apply presence beacons that arrived on the mesh.
///
/// Each entry was verified against its own signature before it got here, so a
/// peer relaying the room's presence is a courier and not a witness — it cannot
/// invent a member, re-date one, or drop one without the gap simply being
/// filled by the next digest from somebody else. There is deliberately no frame
/// that says "X is gone": absence of a fresh beacon is how a member goes
/// offline, and a leave is a member's own signed departure record. Accepting a
/// third party's word for either would let any member evict anyone.
///
/// With an `admission_key` — a private room's current content key — a member
/// the roster does not hold is admitted only on their own proof of that key
/// ([`ember::channel::PresenceBeacon::proves_key`]). Neither the frame's seal
/// nor the signed epoch will do: a digest is sealed by whoever assembled it,
/// possibly a member who picked the beacon up while still on an epoch its
/// author was then evicted from, and the epoch is a number the author picks.
/// Admitting on either would let an evicted member's fresh identity onto the
/// roster the owner re-seals each new epoch to. Members already on the roster
/// need no proof.
#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_channel_presence_beacons(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    ch: &crate::storage::database::StoredChannel,
    gossip: &ember::channel::ChannelGossip,
    beacons: Vec<ember::channel::PresenceBeacon>,
    from_id: ember::dht::EmberNodeId,
    admission_key: Option<[u8; 32]>,
) {
    let now = chrono::Utc::now().timestamp();
    let channel_id = gossip.channel_id;
    // A single beacon is somebody announcing an arrival or a departure and is
    // worth passing on; a batch is one peer's digest of the room, which is
    // already reaching its own neighbors on their own timers. Without this a
    // member could wrap ten beacons in a flooded envelope and have the room
    // amplify all of them at once.
    let announcement = beacons.len() == 1;
    let mut roster_changed = false;
    let mut relay = false;
    // One snapshot for the whole digest. The inserts and removals below each
    // move the roster generation, and re-reading the roster after every one
    // of them would put back the per-beacon queries this replaces; the rows
    // this frame changed are tracked beside it instead.
    let snapshot = channel_roster_snapshot(state, db, channel_id);
    let mut written: HashMap<[u8; 32], Option<bool>> = HashMap::new();
    for beacon in beacons {
        if beacon.member == state.local_ed25519_pubkey {
            continue;
        }
        let Some(at) = beacon.last_seen_at(now) else {
            continue;
        };
        let member_hex = hex::encode(beacon.member);
        let status = written
            .get(&beacon.member)
            .copied()
            .unwrap_or_else(|| snapshot.status(&beacon.member));
        if status == Some(true) {
            continue;
        }
        if status.is_none()
            && admission_key.is_some_and(|key| !beacon.proves_key(&channel_id, &key))
        {
            continue;
        }
        // Anything we already hold that outranks this one settles it. Without
        // this, a member's leave is undone by the next digest from any peer
        // still carrying their last ordinary beacon, and they flicker back into
        // the roster looking online.
        if ember::channel::beacon_superseded(
            state
                .channel_beacons
                .get(&channel_id)
                .and_then(|room| room.get(&beacon.member)),
            &beacon,
        ) {
            continue;
        }
        if beacon.departed {
            // Signed by the member themselves — the loop skipped our own key
            // above, so this can never be a replayed tombstone of ours removing
            // us from a room we are sitting in. `remove_channel_member` is
            // timestamped, so a leave cannot delete a row a newer rejoin wrote.
            if status.is_some()
                && db
                    .remove_channel_member(&ch.channel_id, &member_hex, at)
                    .unwrap_or(false)
            {
                roster_changed = true;
                state.rendezvous_last_register = None;
                written.insert(beacon.member, None);
            }
            // Kept rather than dropped, and passed on in digests like any other
            // beacon. It is signed, so relaying it needs no trust, and holding
            // it is what makes the check above work — the roster row is gone,
            // so this map is the only thing left that remembers the member
            // left rather than simply never having been here.
            remember_channel_beacon(state, channel_id, beacon);
            if announcement && channel_beacon_flood_ok(state, channel_id, &beacon.member, now) {
                relay = true;
            }
            continue;
        }
        if status.is_some() {
            // Buffered like every other liveness touch, and flushed in one
            // transaction by `flush_channel_member_touches`, which is also
            // what reports the rows that moved to the UI. A digest carries up
            // to a roster's worth of beacons, so writing each here was a
            // synchronous fsync per beacon on the network task.
            note_channel_member_alive(state, channel_id, &beacon.member, at);
        } else {
            if !channel_beacon_insert_ok(state, channel_id, now) {
                continue;
            }
            // Nickname is left empty on purpose: a beacon carries no display
            // name, and nothing outside the member's own signed presence record
            // should be able to set one. The presence walk fills it in.
            match db.upsert_channel_member(
                &ch.channel_id,
                &member_hex,
                "",
                at,
                Some(&hex::encode(state.local_ed25519_pubkey)),
            ) {
                Ok(ChannelMemberWrite::Inserted) => {
                    roster_changed = true;
                    // A new member changes who our XOR-neighbors are, so the
                    // pairwise capability they will look us up under has to be
                    // re-registered rather than waiting out the heartbeat.
                    state.rendezvous_last_register = None;
                    written.insert(beacon.member, Some(false));
                }
                // The room is full of members who are neither stale nor exempt.
                // Not cached and not relayed: the beacon map is meant to be
                // bounded by the roster, and a digest is freshest-first, so a
                // burst of invented identities admitted here would ride out in
                // place of the members who are actually present.
                Ok(ChannelMemberWrite::Refused) => continue,
                Ok(_) => {}
                Err(e) => {
                    debug!(
                        "Ember channel presence: roster write failed for {}: {e}",
                        ch.channel_id
                    );
                    continue;
                }
            }
        }
        remember_channel_beacon(state, channel_id, beacon);
        if announcement && channel_beacon_flood_ok(state, channel_id, &beacon.member, now) {
            relay = true;
        }
    }
    if roster_changed {
        // The roster gained or lost somebody. A beacon cannot say who a new
        // member is, only that they are here, and the full list is what carries
        // the nickname and the badges — so ask for it rather than inventing a
        // row. A `last_seen` that merely moved goes out as a delta instead.
        let _ = app_handle.emit(
            "ember:channel-members",
            serde_json::json!({ "channel_id": ch.channel_id }),
        );
    }
    if relay {
        if let Some(next) = gossip.decremented_ttl() {
            fanout_channel_gossip_body(socket, state, db, next.encode(), Some(from_id)).await;
        }
    }
}

/// Which rooms this heartbeat registers neighbors for.
///
/// The room on screen always takes a slot: it is the one whose reachability
/// the user is about to need. The rest of the budget is a window that walks
/// the joined rooms by `beat`, so a room past the cap is registered on a later
/// heartbeat rather than never — the whole of what the fixed cap used to cost
/// a member of five or more rooms. `CHANNEL_RENDEZVOUS_ROTATION_DEPTH` bounds
/// how far that walk may travel before the first room's entry would expire.
///
/// Split from the collection below so the rule can be tested without a
/// `Database`, which has no constructor outside a real store.
pub(super) fn select_rendezvous_rooms(
    roster: &[crate::storage::database::StoredChannel],
    focused: Option<[u8; 16]>,
    beat: u64,
) -> Vec<&crate::storage::database::StoredChannel> {
    let focused_hex = focused.map(hex::encode);
    let mut selected: Vec<&crate::storage::database::StoredChannel> = Vec::new();
    if let Some(ref id) = focused_hex {
        if let Some(ch) = roster
            .iter()
            .find(|c| c.channel_id.eq_ignore_ascii_case(id) && c.in_room_now())
        {
            selected.push(ch);
        }
    }
    // Ordered by `last_active` already, so the window walks from the busiest
    // room outwards and a quiet room is reached within the rotation depth.
    let rest: Vec<&crate::storage::database::StoredChannel> = roster
        .iter()
        .filter(|ch| ch.in_room_now())
        .filter(|ch| {
            !focused_hex
                .as_ref()
                .is_some_and(|id| ch.channel_id.eq_ignore_ascii_case(id))
        })
        .collect();
    if rest.is_empty() {
        return selected;
    }
    let slots = ember::channel::CHANNEL_RENDEZVOUS_MAX_CHANNELS.saturating_sub(selected.len());
    // Only rooms we could not fit rotate. Staying put while everything already
    // fits keeps a settled member's registrations at the same addresses beat
    // after beat rather than churning them for nothing.
    //
    // The window is the rotating slots times the depth, not the fixed
    // coverage: with a room on screen only three slots rotate, and walking
    // eight rooms with them came back to each one every 2.67 beats — past the
    // server's expiry, so registrations lapsed between visits.
    let reachable = rest
        .len()
        .min(slots.saturating_mul(ember::channel::CHANNEL_RENDEZVOUS_ROTATION_DEPTH));
    let start = if reachable > slots && slots > 0 {
        ((beat as usize).saturating_mul(slots)) % reachable
    } else {
        0
    };
    for step in 0..slots.min(reachable) {
        selected.push(rest[(start + step) % reachable]);
    }
    selected
}

/// `roster` comes from [`channels_lite_cached`] so this shares the caller's
/// read rather than running its own `channels` scan on the event loop.
pub(super) fn collect_channel_neighbor_caps(
    db: &Database,
    roster: &[crate::storage::database::StoredChannel],
    our_pubkey: &[u8; 32],
    focused: Option<[u8; 16]>,
    beat: u64,
) -> anyhow::Result<Vec<([u8; 16], [u8; 32])>> {
    let selected = select_rendezvous_rooms(roster, focused, beat);
    let mut members_by_channel = Vec::new();
    for ch in selected {
        // One roster query per *selected* room rather than one per *joined*
        // room. Joining is deliberately uncapped, and this runs on paths that
        // fire every second, so the selection above is what keeps a member of
        // twenty rooms from paying twenty blocking queries a tick.
        let Ok(id_bytes) = hex::decode(&ch.channel_id) else {
            continue;
        };
        let Ok(channel_id) = <[u8; 16]>::try_from(id_bytes) else {
            continue;
        };
        members_by_channel.push((channel_id, channel_member_pubkeys(db, &ch.channel_id)));
    }
    Ok(ember::channel::rendezvous_neighbor_targets(
        our_pubkey,
        &members_by_channel,
        ember::channel::CHANNEL_RENDEZVOUS_MAX_CHANNELS,
        ember::channel::CHANNEL_NEIGHBOR_COUNT,
    ))
}

pub(super) async fn load_rendezvous_register_targets(
    db: &Arc<Database>,
    our_pubkey: [u8; 32],
    focused: Option<[u8; 16]>,
    beat: u64,
) -> (
    Vec<([u8; 16], [u8; 32])>,
    Vec<([u8; 16], [u8; 32])>,
) {
    let db = db.clone();
    tokio::task::spawn_blocking(move || {
        let friends = db.get_friend_public_keys().unwrap_or_default();
        // Already off the reactor, so this reads its own roster rather than
        // taking a turn on the shared cache.
        let roster = db.list_channels_lite().unwrap_or_default();
        let neighbors = collect_channel_neighbor_caps(&db, &roster, &our_pubkey, focused, beat)
            .unwrap_or_default();
        (friends, neighbors)
    })
    .await
    .unwrap_or_default()
}

/// How long the channel roster is reused before it is re-read from SQLite.
///
/// The 1 Hz maintenance pass consults the roster from several helpers, each of
/// which ran `list_channels_lite` itself: four full `channels` table scans a
/// second (with `ORDER BY`), as blocking `rusqlite` calls behind one
/// `Mutex<Connection>`, executed directly on the Tokio worker running the
/// network `select!`. Each contends with every `spawn_blocking` DB writer —
/// `wal_checkpoint(TRUNCATE)` and `VACUUM` included — and stalls all
/// networking for as long as it waits. Worse, the per-room due-time gates that
/// decide whether any work actually happens are evaluated *after* the query,
/// so the cost was paid whether or not anything was due.
///
/// Deliberately shorter than every per-room gate this roster feeds (the
/// shortest, the presence beat, is tens of seconds), so nothing observable is
/// scheduled later than it would have been. That is also why there is no
/// explicit invalidation: five seconds is already well inside the resolution
/// any of these decisions have.
pub(super) const CHANNEL_ROSTER_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// Shortest gap between two durable writes of channel member `last_seen`.
/// See [`flush_channel_member_touches`].
pub(super) const CHANNEL_MEMBER_TOUCH_FLUSH_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(10);

/// The channel roster, re-read from SQLite at most once per
/// [`CHANNEL_ROSTER_TTL`]. Returned behind an `Arc` so callers can hold it
/// while mutating `state`, and so sharing it between helpers on one tick costs
/// nothing.
pub(super) fn channels_lite_cached(
    state: &mut NetworkState,
    db: &Database,
) -> Option<Arc<Vec<crate::storage::database::StoredChannel>>> {
    if let Some((roster, read_at)) = &state.channel_roster_cache {
        if read_at.elapsed() < CHANNEL_ROSTER_TTL {
            return Some(roster.clone());
        }
    }
    let roster = Arc::new(db.list_channels_lite().ok()?);
    state.channel_roster_cache = Some((roster.clone(), std::time::Instant::now()));
    Some(roster)
}

pub(super) const CHANNEL_NEIGHBOR_LOOKUP_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(ember::channel::CHANNEL_NEIGHBOR_LOOKUP_RETRY_SECS);
pub(super) const CHANNEL_NEIGHBOR_LOOKUPS_PER_TICK: usize = 4;
pub(super) const CHANNEL_NEIGHBOR_FIND_NODE_PER_TICK: usize = 2;
pub(super) const CHANNEL_PUNCH_POLL_ATTEMPTS: usize = 12;
pub(super) const CHANNEL_PUNCH_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
pub(super) const CHANNEL_PRESENCE_FETCH_PER_TICK: usize = 2;

/// How long to leave a room's presence keys alone before walking them again.
///
/// A room we are alone in is asked about far more often than a settled one. The
/// five-minute cadence is sized for keeping a roster we already have fresh, and
/// applying it to an empty room made the one case where somebody is actually
/// waiting the slowest case there is — they have just joined, or they are first
/// in and somebody else is arriving. Until presence names a second member there
/// is nobody to gossip to either, so chat cannot move until this resolves.
///
/// `member_count` includes us, so 1 means nobody else yet. `focused` is the
/// room the user has open, which is walked at the same rate as an empty one for
/// the same reason: it is the roster somebody is actually reading, so five
/// minutes of staleness in it is five minutes of a member being in the room and
/// not shown there.
pub(super) fn channel_presence_interval(member_count: i64, focused: bool) -> i64 {
    if focused {
        return ember::channel::PRESENCE_FETCH_FOCUSED_SECS;
    }
    if member_count > 1 {
        ember::channel::PRESENCE_FETCH_SECS
    } else {
        ember::channel::PRESENCE_FETCH_EMPTY_SECS
    }
}

/// FIND_VALUE the current (and previous) presence keys for one room.
///
/// Extra FIND_VALUE keys intersect by `file_hash`, which would drop members who
/// only appear in one epoch, so the two keys are walked as independent
/// searches. Returns whether a walk actually started, so the caller can charge
/// it against a per-tick budget.
pub(super) async fn start_channel_presence_fetch(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    ch: &crate::storage::database::StoredChannel,
    channel_id: [u8; 16],
    now: i64,
) -> bool {
    if state
        .ember_channel_presence_searches
        .values()
        .any(|id| *id == channel_id)
    {
        return false;
    }
    // Has to be the same secret the publisher used, because the presence
    // slot's DHT key is derived from it. Reading the raw `join_secret` here
    // while publishing under the current epoch would put the two sides on
    // different keys and members would stop discovering each other outright
    // the first time a room rotated.
    //
    // Members briefly on different epochs therefore cannot see each other's
    // presence. That resolves as they pick up the new key, and it does not
    // block recovery: an epoch record is fetched by a key derived from the
    // channel and our own identity, never from presence.
    let Some(join_secret) = current_channel_join_secret(db, ch) else {
        return false;
    };
    let epoch = ember::channel::presence_epoch(now);
    let current_key = ember::channel::presence_key(&channel_id, &join_secret, epoch);
    let prev_key = ember::channel::presence_key(&channel_id, &join_secret, epoch - 1);
    let mut keys = vec![current_key];
    if prev_key != current_key {
        keys.push(prev_key);
    }
    let mut any = false;
    for key in keys {
        let Some(search_id) = state.ember_search.start_background_find_value(
            ember::dht::EmberNodeId(key),
            Vec::new(),
            state.ember_dht.routing(),
        ) else {
            break;
        };
        seed_ember_local_records(state, search_id, &key, &[]);
        state
            .ember_channel_presence_searches
            .insert(search_id, channel_id);
        drive_ember_search(socket, state, search_id).await;
        any = true;
    }
    if any {
        state.channel_presence_fetch_at.insert(channel_id, now);
    }
    any
}

/// Walk presence for the rooms that are due, so members are learned without
/// prior gossip.
pub(super) async fn maybe_refresh_channel_members(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
) {
    if !settings.ember_native_enabled || db.chat_locked() {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let Some(channels) = channels_lite_cached(state, db) else {
        return;
    };
    let mut started = 0usize;
    for ch in channels.iter() {
        if !ch.in_room_now() {
            continue;
        }
        if started >= CHANNEL_PRESENCE_FETCH_PER_TICK {
            break;
        }
        let Ok(id_bytes) = hex::decode(&ch.channel_id) else {
            continue;
        };
        let Ok(channel_id) = <[u8; 16]>::try_from(id_bytes) else {
            continue;
        };
        let last = state
            .channel_presence_fetch_at
            .get(&channel_id)
            .copied()
            .unwrap_or(0);
        // Even an empty room is not walked more often than this. Count the
        // roster only when that gate is open — the 1 Hz tick used to run
        // COUNT(*) for every joined room on every pass.
        if !ember::channel::schedule_due(last, now, ember::channel::PRESENCE_FETCH_EMPTY_SECS) {
            continue;
        }
        let focused = state.channel_focused == Some(channel_id);
        let fresh = db
            .count_fresh_channel_members(
                &ch.channel_id,
                now,
                ember::channel::PRESENCE_FRESH_SECS,
            )
            .unwrap_or(0);
        if !ember::channel::schedule_due(last, now, channel_presence_interval(fresh, focused)) {
            continue;
        }
        if start_channel_presence_fetch(socket, state, db, ch, channel_id, now).await {
            started += 1;
        }
    }
}

pub(super) const CHANNEL_MODERATION_FETCH_PER_TICK: usize = 2;
pub(super) const CHANNEL_MODERATION_PUBLISH_PER_TICK: usize = 2;

/// FIND_VALUE the owner-signed moderation record (topic, welcome, bans).
/// One key per channel — extra FIND_VALUE keys intersect by `file_hash`.
pub(super) async fn maybe_refresh_channel_moderation(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
) {
    if !settings.ember_native_enabled || db.chat_locked() {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let Some(channels) = channels_lite_cached(state, db) else {
        return;
    };
    let mut started = 0usize;
    for ch in channels.iter() {
        if !ch.in_room_now() {
            continue;
        }
        if started >= CHANNEL_MODERATION_FETCH_PER_TICK {
            break;
        }
        let Ok(id_bytes) = hex::decode(&ch.channel_id) else {
            continue;
        };
        let Ok(channel_id) = <[u8; 16]>::try_from(id_bytes) else {
            continue;
        };
        if state
            .ember_channel_moderation_searches
            .values()
            .any(|id| *id == channel_id)
        {
            continue;
        }
        let last = state
            .channel_moderation_fetch_at
            .get(&channel_id)
            .copied()
            .unwrap_or(0);
        if !ember::channel::schedule_due(last, now, ember::channel::MODERATION_FETCH_SECS) {
            continue;
        }
        let key = ember::channel::moderation_key(&channel_id);
        let Some(search_id) = state.ember_search.start_background_find_value(
            ember::dht::EmberNodeId(key),
            Vec::new(),
            state.ember_dht.routing(),
        ) else {
            break;
        };
        seed_ember_local_records(state, search_id, &key, &[]);
        state
            .ember_channel_moderation_searches
            .insert(search_id, channel_id);
        drive_ember_search(socket, state, search_id).await;
        state.channel_moderation_fetch_at.insert(channel_id, now);
        started += 1;
    }
}

pub(super) fn ingest_channel_moderation_records(
    db: &Database,
    channel_id: [u8; 16],
    records: &[Vec<u8>],
) -> bool {
    if db.chat_locked() {
        return false;
    }
    let channel_id_hex = hex::encode(channel_id);
    let Ok(Some(ch)) = db.get_channel(&channel_id_hex) else {
        return false;
    };
    let Ok(stored_pk) = hex::decode(&ch.pubkey) else {
        return false;
    };
    let mut best: Option<ember::dht::publish::ChannelModeration> = None;
    for blob in records {
        let Some(parsed) =
            ember::dht::publish::SignedRecord::parse_channel_moderation(blob, &channel_id)
        else {
            continue;
        };
        if stored_pk.as_slice() != parsed.publisher_key.as_slice() {
            continue;
        }
        if best.as_ref().is_none_or(|cur| {
            ember::dht::publish::moderation_supersedes(
                parsed.timestamp,
                &parsed.signature,
                cur.timestamp,
                Some(&cur.signature),
            )
        }) {
            best = Some(parsed);
        }
    }
    let Some(moderation) = best else {
        return false;
    };
    let applied = db
        .ingest_channel_moderation(
            &channel_id_hex,
            &crate::storage::database::ModerationSnapshot {
                topic: &moderation.topic,
                welcome: &moderation.welcome,
                banned_pubkeys: &moderation.banned_pubkeys,
                moderator_pubkeys: &moderation.moderator_pubkeys,
                owner_pubkey: moderation.tail.owner_pubkey.as_ref(),
                successor_nominee: moderation.tail.successor_nominee.as_ref(),
                claim_after_days: moderation.tail.claim_after_days,
                key_epoch: moderation.tail.key_epoch,
                invites_owner_only: moderation.tail.invites_owner_only,
                slow_mode_secs: moderation.tail.slow_mode_secs,
            },
            moderation.timestamp,
            &moderation.signature,
        )
        .unwrap_or(false);
    // Only from a snapshot just accepted as the owner's newest, so an older
    // record replayed from a slow storer cannot rename the room back. Never on
    // the owner's own device: its name is the one it renamed the room to, and
    // a snapshot of its own signed before the rename would quietly undo it here
    // while the registry and every member moved on.
    if applied {
        if let Some(name) = moderation.tail.room_name.as_deref().filter(|_| !ch.is_owner) {
            if let Err(e) = db.apply_owner_room_name(&channel_id_hex, name) {
                tracing::warn!("Channel {channel_id_hex}: could not apply the owner's room name: {e}");
            }
        }
        if let Err(e) = db.apply_owner_room_policy(
            &channel_id_hex,
            moderation.tail.announce_only == Some(true),
            &moderation.tail.pinned_msg_ids,
            moderation.tail.language,
        ) {
            tracing::warn!("Channel {channel_id_hex}: could not apply the owner's pins, posting rule and language: {e}");
        }
    }
    applied
}

/// Owners re-STORE the records only they can sign, so the 24h DHT TTL cannot
/// age them out: the moderation record, plus the public-index listing for
/// public rooms. Both share that TTL, and remaining life is derived from the
/// publisher's signed creation time, so replication between storers cannot
/// stand in for the owner re-signing (see `DhtStore::store`).
pub(super) async fn maybe_publish_owned_channel_records(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
    identity: &crate::storage::identity::NodeIdentity,
) {
    // The gossip handlers cannot reach `AppSettings`, so keep their copy of the
    // Rendezvous URL current from the loop that can.
    if settings.rendezvous_url != state.rendezvous_url {
        state.rendezvous_url = settings.rendezvous_url.clone();
    }
    if !settings.ember_native_enabled || db.chat_locked() {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let Some(channels) = channels_lite_cached(state, db) else {
        return;
    };
    let mut started = 0usize;
    for ch in channels.iter() {
        if ch.deleted {
            continue;
        }
        if started >= CHANNEL_MODERATION_PUBLISH_PER_TICK {
            break;
        }
        if !ch.is_owner {
            continue;
        }
        if !ch.successor_id.is_empty() {
            continue;
        }
        let Ok(id_bytes) = hex::decode(&ch.channel_id) else {
            continue;
        };
        let Ok(channel_id) = <[u8; 16]>::try_from(id_bytes) else {
            continue;
        };
        let last = state
            .channel_moderation_publish_at
            .get(&channel_id)
            .copied()
            .unwrap_or(0);
        if !ember::channel::schedule_due(last, now, ember::channel::MODERATION_REPUBLISH_SECS) {
            continue;
        }
        let Ok(Some(seed)) = db.load_channel_owner_seed(&ch.channel_id) else {
            continue;
        };
        let ident = ember::channel::ChannelIdentity::from_seed(&seed);
        if ident.channel_id != channel_id {
            continue;
        }
        let private = ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE;
        // A delegated moderator's ban has to become an eviction, and only this
        // device can make it one: an epoch record is signed by the room
        // identity, whose seed is ours alone. Done here rather than where the
        // ban is ingested because the snapshot below is the only thing that
        // tells members a new epoch exists, and the re-seal at the end of this
        // pass is what hands it to each of them — the three have to travel
        // together, exactly as `rotate_and_commit` keeps them together for the
        // owner's own bans.
        // Borrowed from the shared roster until a rotation forces a re-read,
        // so the common path does not copy the row.
        let mut ch = std::borrow::Cow::Borrowed(ch);
        let rotated = if private && db.channel_rotate_is_pending(&ch.channel_id).unwrap_or(false) {
            let minted = rotate_owned_channel_key(db, &ch.channel_id, ch.key_epoch);
            if minted.is_some() {
                // Re-read: the snapshot's tail and the re-seal both take the
                // epoch from this row.
                if let Ok(Some(fresh)) = db.get_channel(&ch.channel_id) {
                    ch = std::borrow::Cow::Owned(fresh);
                }
            }
            minted
        } else {
            None
        };
        // Stamped before the state is read, and read from the table rather
        // than the cached roster: an owner edit committed after this stamp
        // carries a later one, and one committed before it is what gets read,
        // so this republish can never undo an edit for the room.
        let Ok(Some(stamp)) = db.stamp_owner_snapshot(&ch.channel_id, now) else {
            undo_owned_rotation(db, &ch.channel_id, rotated);
            continue;
        };
        if let Ok(Some(fresh)) = db.get_channel_lite(&ch.channel_id) {
            ch = std::borrow::Cow::Owned(fresh);
        }
        let mut bans = db
            .list_banned_channel_pubkeys(&ch.channel_id)
            .unwrap_or_default();
        // Same rule as `commands::channels::load_banned_pubkeys`: never re-sign
        // our own key into the ban list of a room we own, or a moderator's
        // gossip becomes an owner-signed ban that outlives every republish.
        let our_pk = state.local_ed25519_pubkey;
        bans.retain(|pk| pk != &our_pk);
        let mods = db
            .list_moderator_channel_pubkeys(&ch.channel_id)
            .unwrap_or_default();
        let record = ember::dht::publish::SignedRecord::channel_moderation_at(
            &ch.topic,
            &ch.welcome,
            &bans,
            &mods,
            // We own this room, so our own identity is the owner identity every
            // member needs in order to refuse a ban aimed at us, and our epoch
            // is how they tell they are behind.
            &ember::dht::publish::ModerationTail {
                owner_pubkey: Some(our_pk),
                key_epoch: Some(ch.key_epoch.max(0) as u64),
                // Zeros rather than absent when unset, so withdrawing a
                // nomination actually reaches members.
                successor_nominee: Some(
                    hex::decode(&ch.successor_nominee)
                        .ok()
                        .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        .unwrap_or([0u8; 32]),
                ),
                claim_after_days: Some(ch.claim_after_days.clamp(0, u16::MAX as i64) as u16),
                invites_owner_only: Some(ch.invites_owner_only),
                // Carried on every republish, not just the edit that set it:
                // this record is a whole snapshot, so omitting it here would
                // turn slow mode off across the room a few hours after the
                // owner switched it on. Absent when off, so a room that never
                // uses it keeps publishing a tail older builds can read.
                slow_mode_secs: match ch.slow_mode_secs.clamp(0, u16::MAX as i64) as u16 {
                    0 => None,
                    secs => Some(secs),
                },
                // Carried on every republish once the room has been renamed, so
                // a member who was offline for the edit still catches up.
                room_name: (ch.renamed_at > 0).then(|| ch.name.clone()),
                // Both on every republish for the same reason as slow mode, and
                // absent when unused so other rooms' tails are unchanged. Pins
                // this device has since removed are left out; `channel_moderation`
                // sheds any that no longer fit. The removal check decrypts
                // nothing and is skipped for a room with no pins, which keeps
                // it cheap enough for this task.
                announce_only: ch.announce_only.then_some(true),
                pinned_msg_ids: {
                    let removed = db
                        .channel_messages_removed(&ch.channel_id, &ch.pinned_msg_ids)
                        .unwrap_or_default();
                    ch.pinned_msg_id_bytes()
                        .into_iter()
                        .filter(|id| !removed.contains(&hex::encode(id)))
                        .collect()
                },
                // Every republish, like the pins, so a member who joins later
                // still sees the room's language.
                language: ember::dht::publish::channel_language(&ch.language),
            },
            channel_id,
            ident.pubkey,
            private,
            &ident.signing_key,
            stamp,
        );
        // A snapshot too large for one record cannot be republished at all, and
        // the copy the network holds expires within the day. Say so once per
        // refresh rather than letting the room quietly lose its governance.
        let Some(record) = record else {
            warn!(
                "Ember: channel {} moderation snapshot does not fit one record; its published \
                 state will lapse until the welcome or the ban/moderator lists are shortened",
                hex::encode(channel_id)
            );
            undo_owned_rotation(db, &ch.channel_id, rotated);
            continue;
        };
        let Some(publish_id) = state
            .ember_publish
            .start_publish(record, state.ember_dht.routing())
        else {
            undo_owned_rotation(db, &ch.channel_id, rotated);
            continue;
        };
        {
            state.channel_moderation_publish_at.insert(channel_id, now);
            // The ban is now an eviction: the snapshot naming the new epoch is
            // on its way, and the re-seal at the end of this pass reaches
            // everyone still entitled to it.
            if rotated.is_some() {
                let _ = db.clear_channel_rotate_pending(&ch.channel_id);
            }
            drive_ember_publish(socket, state, publish_id).await;
            started += 1;
            // Everything a room's survival depends on is renewed from here, so
            // this loop running *is* the owner's liveness signal: the directory
            // entry, the name claim, and the succession clock all age from the
            // last pass. Walking out of a room you own is not abandonment and
            // must not start that clock — closing Ember for good is, and that
            // stops this loop on its own.
            if !settings.rendezvous_url.is_empty() {
                let url = settings.rendezvous_url.clone();
                let cid = ident.channel_id;
                let cpk = ident.pubkey;
                let seed = ident.seed();
                let cname = ch.name.clone();
                // A room we inherited still has its name bound to the room it
                // came from, and the handover at claim time is one shot — it
                // fails whenever Rendezvous happens to be unreachable. Retrying
                // it here is what makes that recoverable rather than a wait for
                // the abandoned name to lapse.
                let predecessor = hex::decode(&ch.predecessor_id)
                    .ok()
                    .and_then(|b| <[u8; 16]>::try_from(b).ok());
                // Whoever we nominated has to be on record with the registry or
                // they cannot take the name when they take the room. Sent from
                // here as well as at nomination time, because that one-shot is
                // lost if the registry was unreachable — or if the room had no
                // name claim yet for the nomination to attach to. Sent when
                // there is no nominee too, so a withdrawal that did not land —
                // a ban of the nominee while the registry was down — is not
                // left standing there. A nominee banned by a moderator's
                // gossip is withdrawn the same way: members already refuse
                // their claim, and the registry must not let them move the name.
                let nominee = hex::decode(&ch.successor_nominee)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .filter(|_| ch.claim_after_days > 0)
                    .filter(|_| {
                        !db.channel_member_is_banned(&ch.channel_id, &ch.successor_nominee)
                            .unwrap_or(false)
                    });
                let claim_after_days = ch.claim_after_days.clamp(0, u32::MAX as i64) as u32;
                let our_pk = identity.ed25519_public_key;
                let our_sk = identity.ed25519_secret_key;
                tokio::spawn(async move {
                    let claimed = crate::network::rendezvous::claim_channel_name(
                        &url, &cid, &cpk, &seed, &cname, private,
                    )
                    .await;
                    if claimed.is_ok() {
                        if let Err(error) = crate::network::rendezvous::register_channel_nominee(
                            &url,
                            &cid,
                            &cpk,
                            &seed,
                            nominee.as_ref(),
                            claim_after_days,
                        )
                        .await
                        {
                            tracing::debug!(?error, "could not re-register the room's nominee");
                        }
                        return;
                    }
                    let taken = matches!(
                        claimed,
                        Err(crate::network::rendezvous::ChannelRegistryError::Taken)
                    );
                    let Some(old_id) = predecessor.filter(|_| taken) else {
                        return;
                    };
                    // Twice. Once the name is bound here, this room's own key is
                    // what the registry counts as the room being alive, however
                    // it changed hands. The user key is what moves the name on a
                    // nominee's takeover, and what a registry from before that
                    // rule still counts.
                    let as_room = crate::network::rendezvous::handover_channel_name(
                        &url, &old_id, &cid, &cpk, &cpk, &seed,
                    )
                    .await;
                    let as_user = crate::network::rendezvous::handover_channel_name(
                        &url, &old_id, &cid, &cpk, &our_pk, &our_sk,
                    )
                    .await;
                    if let (Err(room), Err(user)) = (as_room, as_user) {
                        tracing::debug!(
                            ?room,
                            ?user,
                            "could not move the inherited channel name"
                        );
                    }
                });
            }
            // The listing Discover walks was published once, at creation, so an
            // established room aged out of the index after a day while its
            // members carried on none the wiser. Renewed on the same cadence
            // because this is the only loop that already holds the room key,
            // and 6h against a 24h TTL survives a missed pass.
            if !private {
                let index = ember::dht::publish::SignedRecord::channel_index(
                    &ch.name,
                    channel_id,
                    ident.pubkey,
                    false,
                    Some(ch.language.as_str()).filter(|l| !l.is_empty()),
                    &ident.signing_key,
                );
                if let Some(index_id) = state
                    .ember_publish
                    .start_publish(index, state.ember_dht.routing())
                {
                    drive_ember_publish(socket, state, index_id).await;
                }
            }
            // Renew the current epoch alongside it. Rotation publishes these
            // once, on the ban, and if that pass failed — app closed mid-way, no
            // route to the storing nodes, records aged out — every remaining
            // member is locked out of a room they are still entitled to read,
            // with nothing to re-ask of. This is the recovery path, and it is
            // cheap: republishing an epoch a member already holds is a no-op.
            if private && ch.key_epoch > 0 {
                republish_channel_key_epoch(socket, state, db, &ch, &ident, identity, our_pk).await;
            }
        }
    }
}

/// Drop an epoch whose moderation snapshot never went out, so the room keeps
/// talking under the key its members still hold.
pub(super) fn undo_owned_rotation(db: &Database, channel_id_hex: &str, rotated: Option<i64>) {
    let Some(epoch) = rotated else {
        return;
    };
    if let Err(error) = db.rollback_channel_key_epoch(channel_id_hex, epoch) {
        tracing::error!(
            channel_id = %channel_id_hex,
            %error,
            "could not roll back epoch {epoch} after its snapshot failed to publish"
        );
    }
}

/// Mint the next content-key epoch for a private room we own.
///
/// Returns the new epoch number. The caller has to announce it in the moderation
/// snapshot and roll it back if that snapshot does not go out: members only ever
/// fetch an epoch a snapshot has named, so a rotation nobody was told about
/// leaves the owner sealing traffic under a key the room cannot find.
pub(super) fn rotate_owned_channel_key(db: &Database, channel_id_hex: &str, from_epoch: i64) -> Option<i64> {
    let next = from_epoch.saturating_add(1);
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
    match db.insert_channel_key_epoch(channel_id_hex, next, &secret) {
        Ok(()) => Some(next),
        Err(error) => {
            tracing::warn!(
                channel_id = %channel_id_hex,
                %error,
                "could not mint a rotated content key for a moderator's ban"
            );
            None
        }
    }
}

/// Re-seal the room's current content key to every member still entitled to it.
///
/// Skips banned members and ourselves, exactly as the rotation did. Reads the
/// `banned` flag from the database, which is safe here because any ban that
/// triggered a rotation was committed long before this timer runs.
///
/// Every unbanned row is taken as entitled, which holds only because a new row
/// needs evidence that its *author* held the current key — not merely that
/// whoever sealed the frame did:
/// - a DHT presence record, whose extra the member seals themselves and
///   storers only hold;
/// - a beacon carrying the member's own key proof, checked against our current
///   key in [`apply_channel_presence_beacons`];
/// - a live chat line opened under the current key, whose seal is the author's
///   because relays forward the original body. Catch-up re-serves are sealed
///   by the responder and never admit ([`ember::channel::chat_author_joins_gossip_roster`]).
///
/// The remaining writers are the owner's own snapshot, a moderator's signed
/// action, and a handoff copying the old roster — each an authority over who
/// is in the room. What this does not cover is a member who holds the current
/// key and chooses to vouch for someone: they could as easily hand that
/// someone the key.
pub(super) async fn republish_channel_key_epoch(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    ch: &crate::storage::database::StoredChannel,
    ident: &ember::channel::ChannelIdentity,
    identity: &crate::storage::identity::NodeIdentity,
    our_pk: [u8; 32],
) {
    let epoch = ch.key_epoch;
    let Some(secret) = db
        .load_channel_key_epochs(&ch.channel_id)
        .unwrap_or_default()
        .into_iter()
        .find(|(e, _)| *e == epoch)
        .map(|(_, secret)| secret)
    else {
        return;
    };
    let our_seed = identity.ed25519_secret_key;
    for member in db.list_channel_members(&ch.channel_id).unwrap_or_default() {
        if member.banned {
            continue;
        }
        let Some(member_pk) = hex::decode(&member.member_pubkey)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            continue;
        };
        if member_pk == our_pk {
            continue;
        }
        let Some(wrap) = ember::channel::derive_channel_epoch_secret(
            &our_seed,
            &member_pk,
            &ident.channel_id,
            epoch,
        ) else {
            continue;
        };
        let sealed =
            ember::channel::seal_channel_key_epoch(&wrap, &ident.channel_id, epoch, &secret);
        let record = ember::dht::publish::SignedRecord::channel_key_epoch(
            ident.channel_id,
            ident.pubkey,
            &member_pk,
            epoch,
            &sealed,
            &ident.signing_key,
        );
        if let Some(publish_id) = state
            .ember_publish
            .start_publish(record, state.ember_dht.routing())
        {
            drive_ember_publish(socket, state, publish_id).await;
        }
    }
}

pub(super) const CHANNEL_EPOCH_FETCH_PER_TICK: usize = 2;
/// Re-ask for an epoch record we could not find yet. Short, because until it
/// lands the member cannot read anything new in the room.
pub(super) const CHANNEL_EPOCH_FETCH_SECS: i64 = 60;

/// FIND_VALUE our own copy of a rotated content key.
///
/// Only for private rooms we do not own: the owner mints epochs, and a public
/// room's key is derivable by anyone so rotating one would evict nobody. Driven
/// by `key_epoch_wanted` running ahead of `key_epoch`, both of which come from
/// the owner's signed moderation record.
pub(super) async fn maybe_refresh_channel_key_epoch(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
    identity: &crate::storage::identity::NodeIdentity,
) {
    if !settings.ember_native_enabled || db.chat_locked() {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let Some(channels) = channels_lite_cached(state, db) else {
        return;
    };
    let our_pk = identity.ed25519_public_key;
    let mut started = 0usize;
    for ch in channels.iter() {
        if !ch.in_room_now() {
            continue;
        }
        if started >= CHANNEL_EPOCH_FETCH_PER_TICK {
            break;
        }
        if ch.is_owner
            || ch.visibility != ember::channel::CHANNEL_KIND_PRIVATE
            || ch.key_epoch_wanted <= 0
            || !ch.successor_id.is_empty()
        {
            continue;
        }
        let Ok(channel_id) = hex::decode(&ch.channel_id)
            .map_err(|_| ())
            .and_then(|b| <[u8; 16]>::try_from(b).map_err(|_| ()))
        else {
            continue;
        };
        let last = state
            .channel_epoch_fetch_at
            .get(&channel_id)
            .copied()
            .unwrap_or(0);
        if !ember::channel::schedule_due(last, now, CHANNEL_EPOCH_FETCH_SECS) {
            continue;
        }
        // The newest epoch we are *missing*, which is not the same as the one
        // the owner advertises. Sleeping through two rotations used to leave the
        // intermediate epoch unfetched for good: the member picked up the
        // newest, `key_epoch` caught up to `key_epoch_wanted`, and the loop
        // stopped looking — so the window of history sealed under the epoch in
        // between stayed unreadable even though its record was still in the DHT
        // and `channel_content_keys` would have used it. Behind the schedule
        // gate so this costs one indexed read per room per interval.
        let floor = (ch.key_epoch_wanted - Database::CHANNEL_KEY_EPOCHS_KEPT as i64 + 1).max(1);
        let Ok(Some(target)) =
            db.newest_missing_channel_key_epoch(&ch.channel_id, floor, ch.key_epoch_wanted)
        else {
            continue;
        };
        if state
            .ember_channel_epoch_searches
            .values()
            .any(|(id, epoch)| *id == channel_id && *epoch == target)
        {
            continue;
        }
        let key = ember::channel::epoch_key(&channel_id, &our_pk, target);
        let Some(search_id) = state.ember_search.start_background_find_value(
            ember::dht::EmberNodeId(key),
            Vec::new(),
            state.ember_dht.routing(),
        ) else {
            break;
        };
        seed_ember_local_records(state, search_id, &key, &[]);
        state
            .ember_channel_epoch_searches
            .insert(search_id, (channel_id, target));
        drive_ember_search(socket, state, search_id).await;
        state.channel_epoch_fetch_at.insert(channel_id, now);
        started += 1;
    }
}

/// Open an epoch record sealed to us and store the key it carries.
///
/// The wrapping key is pairwise with the owner, so a blob sealed to anyone else
/// simply fails to open — which is exactly what makes a ban an eviction.
pub(super) fn ingest_channel_epoch_records(
    db: &Database,
    identity: &crate::storage::identity::NodeIdentity,
    channel_id: [u8; 16],
    epoch: i64,
    records: &[Vec<u8>],
) -> bool {
    if db.chat_locked() {
        return false;
    }
    let channel_id_hex = hex::encode(channel_id);
    let Ok(Some(ch)) = db.get_channel(&channel_id_hex) else {
        return false;
    };
    let Some(owner_pk) = hex::decode(&ch.owner_pubkey)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    else {
        // We have not learned who owns the room, so there is nobody to derive
        // the wrapping key against yet. The moderation poll fixes that.
        return false;
    };
    let Some(wrap) = ember::channel::derive_channel_epoch_secret(
        &identity.ed25519_secret_key,
        &owner_pk,
        &channel_id,
        epoch,
    ) else {
        return false;
    };
    for blob in records {
        let Some((member, record_epoch, envelope)) =
            ember::dht::publish::SignedRecord::parse_channel_key_epoch(blob, &channel_id)
        else {
            continue;
        };
        // Only our own slot, and only for the epoch we asked about: the record
        // is self-validating about both, so a mismatch is somebody else's.
        if member != identity.ed25519_public_key || record_epoch != epoch {
            continue;
        }
        let Some(secret) =
            ember::channel::open_channel_key_epoch(&wrap, &channel_id, epoch, &envelope)
        else {
            continue;
        };
        match db.insert_channel_key_epoch(&channel_id_hex, epoch, &secret) {
            Ok(()) => return true,
            Err(e) => {
                debug!("Ember channel epoch {epoch} for {channel_id_hex} not stored: {e}");
            }
        }
    }
    false
}

pub(super) const CHANNEL_HANDOFF_FETCH_PER_TICK: usize = 2;

/// FIND_VALUE the owner-signed successor record. Separate from moderation:
/// extra FIND_VALUE keys intersect by `file_hash`, and these records share
/// that hash but live under different DHT keys.
pub(super) async fn maybe_refresh_channel_handoff(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
) {
    if !settings.ember_native_enabled || db.chat_locked() {
        return;
    }
    // Rides this timer because it is the handoff loop's own: our committed
    // handoffs are republished here, and finished once this fetch or a
    // publish acknowledgement confirms one is stored.
    maybe_drive_channel_handoffs(socket, state, db).await;
    let now = chrono::Utc::now().timestamp();
    let Some(channels) = channels_lite_cached(state, db) else {
        return;
    };
    let mut started = 0usize;
    for ch in channels.iter() {
        if !ch.in_room_now() {
            continue;
        }
        if started >= CHANNEL_HANDOFF_FETCH_PER_TICK {
            break;
        }
        if !ch.successor_id.is_empty() {
            continue;
        }
        let Ok(id_bytes) = hex::decode(&ch.channel_id) else {
            continue;
        };
        let Ok(channel_id) = <[u8; 16]>::try_from(id_bytes) else {
            continue;
        };
        if state
            .ember_channel_handoff_searches
            .values()
            .any(|id| *id == channel_id)
        {
            continue;
        }
        let last = state
            .channel_handoff_fetch_at
            .get(&channel_id)
            .copied()
            .unwrap_or(0);
        if !ember::channel::schedule_due(last, now, ember::channel::HANDOFF_FETCH_SECS) {
            continue;
        }
        let key = ember::channel::handoff_key(&channel_id);
        let Some(search_id) = state.ember_search.start_background_find_value(
            ember::dht::EmberNodeId(key),
            Vec::new(),
            state.ember_dht.routing(),
        ) else {
            break;
        };
        seed_ember_local_records(state, search_id, &key, &[]);
        state
            .ember_channel_handoff_searches
            .insert(search_id, channel_id);
        drive_ember_search(socket, state, search_id).await;
        state.channel_handoff_fetch_at.insert(channel_id, now);
        started += 1;

        // A succession claim lives under its own key, because it is signed by
        // the nominee rather than the room. Only worth asking for once the
        // owner has actually been silent long enough to honour one.
        if ch.successor_nominee.is_empty()
            || ch.claim_after_days <= 0
            || ch.moderation_updated_at <= 0
            || now.saturating_sub(ch.moderation_updated_at)
                < ch.claim_after_days.saturating_mul(86_400)
        {
            continue;
        }
        if state
            .ember_channel_claim_searches
            .values()
            .any(|id| *id == channel_id)
        {
            continue;
        }
        let claim = ember::channel::claim_key(&channel_id);
        let Some(claim_search) = state.ember_search.start_background_find_value(
            ember::dht::EmberNodeId(claim),
            Vec::new(),
            state.ember_dht.routing(),
        ) else {
            continue;
        };
        seed_ember_local_records(state, claim_search, &claim, &[]);
        state
            .ember_channel_claim_searches
            .insert(claim_search, channel_id);
        drive_ember_search(socket, state, claim_search).await;
    }
}

pub(super) fn ingest_channel_handoff_records(
    db: &Database,
    channel_id: [u8; 16],
    records: &[Vec<u8>],
) -> Option<[u8; 16]> {
    if db.chat_locked() {
        return None;
    }
    let channel_id_hex = hex::encode(channel_id);
    let Ok(Some(ch)) = db.get_channel(&channel_id_hex) else {
        return None;
    };
    let Ok(stored_pk) = hex::decode(&ch.pubkey) else {
        return None;
    };
    let mut best: Option<ember::dht::publish::ChannelHandoff> = None;
    for blob in records {
        let Some(parsed) =
            ember::dht::publish::SignedRecord::parse_channel_handoff(blob, &channel_id)
        else {
            continue;
        };
        if stored_pk.as_slice() != parsed.publisher_key.as_slice() {
            continue;
        }
        // Version first, timestamp only to break a tie. Either-or let a record
        // with the *lower* version win on a newer timestamp, and which one that
        // was depended on the order the DHT happened to return them. That is not
        // a cosmetic preference: `apply_channel_handoff` has no version guard of
        // its own and refuses any later handoff naming a different successor, so
        // picking the stale one here pointed the room at the wrong owner for
        // good.
        if best.as_ref().is_none_or(|cur| {
            parsed.version > cur.version
                || (parsed.version == cur.version && parsed.timestamp > cur.timestamp)
        }) {
            best = Some(parsed);
        }
    }
    let handoff = best?;
    let keep = handoff.flags & ember::channel::HANDOFF_FLAG_KEEP_JOIN_SECRET != 0;
    let successor_pk = hex::encode(handoff.successor_pubkey);
    let successor_id = hex::encode(handoff.successor_channel_id);
    // Our own record, found stored — possibly one whose acknowledgement never
    // came back. It is not applied here: that would drop our seed before the
    // registry name was signed over to the successor. Confirming it hands the
    // rest to `maybe_drive_channel_handoffs`, which does both in order.
    if ch.is_owner {
        let _ = db.confirm_channel_handoff(
            &channel_id_hex,
            handoff.version,
            &successor_pk,
            chrono::Utc::now().timestamp(),
            true,
        );
        return None;
    }
    let seed = db
        .load_handoff_pending_seed(&channel_id_hex, &successor_pk, handoff.version)
        .ok()
        .flatten();
    if db
        .apply_channel_handoff(
            &channel_id_hex,
            &successor_pk,
            &successor_id,
            handoff.version,
            keep,
            seed.as_ref(),
        )
        .unwrap_or(false)
    {
        Some(handoff.successor_channel_id)
    } else {
        None
    }
}

/// Honour a nominee's claim on a room whose owner has gone silent.
///
/// The claim itself proves nothing — it is signed by the claimant, who has
/// every reason to publish one. What makes it safe is that each member decides
/// independently, against facts only the owner could have authored: the
/// nomination in their last signed moderation record, and the timestamp of that
/// record.
///
/// The awkward part is that "the owner is silent" and "we have not looked" are
/// the same observation from here. So the window is measured from the *newest*
/// evidence available — ours or the claim's own — and only once
/// [`owner_silence_is_confirmed`] says we have actually been asking.
pub(super) fn ingest_channel_claim_records(
    db: &Database,
    channel_id: [u8; 16],
    records: &[Vec<u8>],
) -> Option<[u8; 16]> {
    if db.chat_locked() {
        return None;
    }
    let channel_id_hex = hex::encode(channel_id);
    let Ok(Some(ch)) = db.get_channel(&channel_id_hex) else {
        return None;
    };
    if !ember::channel::owner_silence_is_confirmed(ch.moderation_checked_at) {
        return None;
    }
    if !ch.successor_id.is_empty() || ch.is_owner {
        return None;
    }
    // Succession is opt-in: no nomination, or no window, means the owner never
    // set it up and the room stays as it is.
    if ch.successor_nominee.is_empty() || ch.claim_after_days <= 0 {
        return None;
    }
    if ch.moderation_updated_at <= 0 {
        // We have never held an owner-signed record, so we have no idea how
        // long they have been quiet and no nomination we can trust.
        return None;
    }
    let now = chrono::Utc::now().timestamp();
    let silent_for = now.saturating_sub(ch.moderation_updated_at);
    let required = ch.claim_after_days.saturating_mul(86_400);
    if silent_for < required {
        return None;
    }
    // Pick one claim by a rule every member applies identically, rather than
    // whichever the DHT happened to return first. A nominee can publish two
    // claims naming different successor rooms; first-wins would let members
    // follow different ones and split the room, which is exactly what
    // succession is supposed to avoid. Newest witness wins, ties broken on the
    // successor id so the ordering is total.
    let mut candidates: Vec<([u8; 32], [u8; 32], [u8; 16], i64, bool)> = records
        .iter()
        .filter_map(|blob| {
            ember::dht::publish::SignedRecord::parse_channel_succession_claim(blob, &channel_id)
        })
        .collect();
    candidates.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| a.2.cmp(&b.2)));
    for (claimant, successor_pk, successor_id, witnessed_ts, keep) in candidates {
        let claimant_hex = hex::encode(claimant);
        if !ch.successor_nominee.eq_ignore_ascii_case(&claimant_hex) {
            continue;
        }
        // A nominee who was banned before the owner went quiet does not inherit
        // the room. The owner clears the nomination when they ban, but their
        // final record may never have reached us, so this is checked again here
        // against the ban we do hold.
        if db
            .channel_member_is_banned(&channel_id_hex, &claimant_hex)
            .unwrap_or(true)
        {
            continue;
        }
        // A claimant cannot backdate the owner's last word: they may only cite
        // a record at least as new as the one we hold.
        if witnessed_ts < ch.moderation_updated_at {
            continue;
        }
        // And their own evidence has to clear the window too. Checking only our
        // local copy meant a claim that openly cited a record from an hour ago
        // was still honoured by anyone whose snapshot happened to be older —
        // the claimant proved the owner was alive and inherited the room anyway.
        if now.saturating_sub(witnessed_ts) < required {
            continue;
        }
        let successor_pk_hex = hex::encode(successor_pk);
        let successor_id_hex = hex::encode(successor_id);
        if db
            .apply_channel_handoff(
                &channel_id_hex,
                &successor_pk_hex,
                &successor_id_hex,
                // Version is the claim's own witness timestamp: monotonic, and
                // it cannot collide with the owner's own handoff versions.
                witnessed_ts.max(1) as u64,
                keep,
                None,
            )
            .unwrap_or(false)
        {
            tracing::info!(
                channel_id = %channel_id_hex,
                "followed a succession claim after {silent_for}s of owner silence"
            );
            return Some(successor_id);
        }
    }
    None
}

/// What applying a presence FIND_VALUE batch did to this room.
pub(super) struct ChannelPresenceIngest {
    /// A member we did not already hold (not us). XOR-neighbors may have changed.
    pub(super) new_neighbors: bool,
    /// last_seen, nickname, join, or leave actually moved — the roster UI
    /// has to refresh. Distinct from `new_neighbors`: a republish from
    /// someone already on the list is not a new XOR-neighbor, but it *is*
    /// the last_seen the presence dot reads.
    pub(super) roster_changed: bool,
}

pub(super) fn ingest_channel_presence_records(
    state: &mut NetworkState,
    db: &Database,
    our_pubkey: &[u8; 32],
    channel_id: [u8; 16],
    records: &[Vec<u8>],
) -> ChannelPresenceIngest {
    let mut outcome = ChannelPresenceIngest {
        new_neighbors: false,
        roster_changed: false,
    };
    if db.chat_locked() {
        return outcome;
    }
    let channel_id_hex = hex::encode(channel_id);
    let Ok(Some(ch)) = db.get_channel(&channel_id_hex) else {
        return outcome;
    };
    if !ch.in_room_now() {
        return outcome;
    }
    // A private room's presence extra is sealed under the content key, so a
    // member who has not yet picked up the newest epoch is still readable under
    // the one they published with.
    let content_keys = channel_content_keys(db, &ch);
    // Current and previous epoch are two FIND_VALUE walks. Newest-wins has
    // to see both before any row is written, or a prev-epoch live announce
    // re-inserts after the current tombstone and a prev-epoch tombstone
    // deletes a rejoiner. Equal timestamps prefer the leave.
    let now = chrono::Utc::now().timestamp();
    let mut latest: HashMap<[u8; 32], ember::dht::publish::ChannelPresenceMember> =
        HashMap::new();
    // Publishers with at least one record sealed under the current key. Only
    // they may be added to the roster: a retired key is also what a rotation's
    // evicted member holds, and a record under one from a key the roster has
    // never seen is that member under a new name.
    let mut current: HashSet<[u8; 32]> = HashSet::new();
    for blob in records {
        let Some((member, opened)) =
            ember::channel::open_with_content_keys(&content_keys, |candidate| {
                ember::dht::publish::SignedRecord::parse_channel_presence_member(
                    blob,
                    &channel_id,
                    Some(candidate),
                )
            })
        else {
            continue;
        };
        if opened == ember::channel::OpenedUnder::Current {
            current.insert(member.publisher_key);
        }
        let Some(ts) = ember::channel::clamp_presence_timestamp(member.timestamp, now) else {
            continue;
        };
        let mut member = member;
        member.timestamp = ts;
        ember::dht::publish::keep_latest_presence_member(&mut latest, member);
    }
    let our_hex = hex::encode(our_pubkey);
    for member in latest.into_values() {
        let pk_hex = hex::encode(member.publisher_key);
        if member.departed {
            if !ember::channel::presence_departure_applies(
                &member.publisher_key,
                our_pubkey,
                ch.in_room_now(),
            ) {
                continue;
            }
            match db.remove_channel_member(&channel_id_hex, &pk_hex, member.timestamp) {
                Ok(true) => {
                    if member.publisher_key != *our_pubkey {
                        // The departed member may have been a gossip neighbor.
                        outcome.new_neighbors = true;
                        outcome.roster_changed = true;
                    }
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(
                        channel_id = %channel_id_hex,
                        member = %pk_hex,
                        error = %e,
                        "could not apply a presence leave tombstone"
                    );
                }
            }
            state.ember_channel_noise_keys.remove(&member.publisher_key);
            continue;
        }
        if !current.contains(&member.publisher_key)
            && !matches!(db.channel_member_status(&channel_id_hex, &pk_hex), Ok(Some(_)))
        {
            continue;
        }
        let nick = crate::security::sanitize_display_name(&member.nickname);
        if let Ok(write) = db.upsert_channel_member(
            &channel_id_hex,
            &pk_hex,
            &nick,
            member.timestamp,
            Some(&our_hex),
        ) {
            // A refused newcomer holds no row, so it gets no key cached
            // either: that map is sized to the rosters it serves.
            if write == ChannelMemberWrite::Refused {
                continue;
            }
            state
                .ember_channel_noise_keys
                .insert(member.publisher_key, member.noise_pub);
            match write {
                ChannelMemberWrite::Inserted => {
                    if member.publisher_key != *our_pubkey {
                        outcome.new_neighbors = true;
                    }
                    outcome.roster_changed = true;
                }
                // The nickname moved, so the row has to be re-read to be drawn.
                ChannelMemberWrite::Updated => {
                    outcome.roster_changed = true;
                }
                // A routine republish from somebody already on the list. One
                // number changed, and it goes out as that rather than as a
                // reason to rebuild the room's whole roster. `member.timestamp`
                // was clamped when the batch was merged.
                ChannelMemberWrite::Touched => {
                    if member.publisher_key != *our_pubkey {
                        mark_channel_presence_dirty(
                            state,
                            channel_id,
                            &member.publisher_key,
                            member.timestamp,
                        );
                    }
                }
                ChannelMemberWrite::Unchanged | ChannelMemberWrite::Refused => {}
            }
        }
    }
    outcome
}

/// Hold presence blobs until every FIND_VALUE for this room (current and
/// previous epoch) has finished, then queue one newest-wins ingest.
pub(super) fn buffer_channel_presence_records(
    state: &mut NetworkState,
    channel_id: [u8; 16],
    records: Vec<Vec<u8>>,
) {
    if !records.is_empty() {
        state
            .ember_channel_presence_buffer
            .entry(channel_id)
            .or_default()
            .extend(records);
    }
    flush_channel_presence_if_idle(state, channel_id);
}

pub(super) fn flush_channel_presence_if_idle(state: &mut NetworkState, channel_id: [u8; 16]) {
    if state
        .ember_channel_presence_searches
        .values()
        .any(|id| *id == channel_id)
    {
        return;
    }
    if let Some(records) = state.ember_channel_presence_buffer.remove(&channel_id) {
        state
            .ember_pending_channel_presence
            .push((channel_id, records));
    }
}

/// How long [`maybe_dial_channel_neighbors`] waits before re-reading the
/// channel member roster after a pass that started no lookups.
///
/// Well under `CHANNEL_NEIGHBOR_LOOKUP_RETRY_SECS` (30s), so backing off cannot
/// delay a retry that is actually due; it only stops the 1 Hz maintenance tick
/// from re-running the same SQLite reads to reach the same conclusion.
pub(super) const CHANNEL_NEIGHBOR_IDLE_RESCAN: std::time::Duration = std::time::Duration::from_secs(5);
