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
mod membership_record_v2_tests {
    use super::{
        channel_epoch_lookup, ingest_channel_epoch_records, merge_channel_presence_blobs,
        ChannelEpochIngest,
    };
    use crate::network::ember::channel::{self, ChannelIdentity};
    use crate::network::ember::dht::publish::SignedRecord;
    use crate::storage::database::Database;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn blob(record: &SignedRecord) -> Vec<u8> {
        let mut blob = record.data.clone();
        blob.extend_from_slice(&record.signature);
        blob
    }

    /// Of a member's two forms stamped alike, the v2 one is what is read; a
    /// member with only a v1 record is still read; a v2 record whose seal was
    /// lifted into another pseudonym's record names nobody; and only the
    /// current secret's records admit.
    #[test]
    fn presence_reads_v2_first_and_falls_back_to_v1() {
        let room = ChannelIdentity::generate();
        let current = [0x21u8; 32];
        let retired = [0x20u8; 32];
        let secrets = [current, retired];
        let now = 1_800_000_000;
        let ada = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let cy = SigningKey::generate(&mut OsRng);
        let pk = |key: &SigningKey| key.verifying_key().to_bytes();

        let ada_v1 = SignedRecord::channel_presence_v1_at(
            "ada (v1)", None, room.channel_id, room.pubkey, &current, true, channel::presence_epoch(now), false, &[1; 32], &ada, now,
        );
        let ada_v2 =
            SignedRecord::channel_presence_v2_at("ada", Some("ja"), room.channel_id, &current, false, &[2; 32], &ada, now);
        let bob_v1 = SignedRecord::channel_presence_v1_at(
            "bob", Some("de"), room.channel_id, room.pubkey, &current, true, channel::presence_epoch(now), false, &[3; 32], &bob, now,
        );
        let cy_v2 = SignedRecord::channel_presence_v2_at("cy", None, room.channel_id, &retired, false, &[4; 32], &cy, now);
        let storer = SigningKey::generate(&mut OsRng);
        let mut lifted = ada_v2.clone();
        lifted.publisher_key = pk(&storer);
        lifted.data[73..105].copy_from_slice(&lifted.publisher_key);
        lifted.signature = crate::network::ember::crypto::sign(&storer, &lifted.data);

        for blobs in [
            vec![blob(&ada_v2), blob(&ada_v1), blob(&bob_v1), blob(&cy_v2), blob(&lifted)],
            vec![blob(&ada_v1), blob(&ada_v2), blob(&lifted), blob(&cy_v2), blob(&bob_v1)],
        ] {
            let (latest, admits) = merge_channel_presence_blobs(&blobs, &room.channel_id, &secrets, true, now);
            assert_eq!(latest.len(), 3, "the lifted seal names nobody");
            assert_eq!(latest[&pk(&ada)].nickname, "ada");
            assert_eq!(latest[&pk(&ada)].noise_pub, [2; 32]);
            assert_eq!(latest[&pk(&ada)].language, Some("ja"), "the v2 copy stands");
            assert_eq!(latest[&pk(&bob)].nickname, "bob");
            assert_eq!(latest[&pk(&bob)].language, Some("de"));
            assert_eq!(latest[&pk(&cy)].nickname, "cy");
            assert_eq!(latest[&pk(&cy)].language, None);
            assert!(!latest.contains_key(&pk(&storer)));
            assert!(admits.contains(&pk(&ada)) && admits.contains(&pk(&bob)));
            assert!(!admits.contains(&pk(&cy)), "a retired secret does not admit");
        }

        // A v1 record that is neither flagged private nor sealed — a bare
        // 32-byte extra, which anyone who knows the room's id and pubkey can
        // sign under a fresh key — is no member of a private room, and above
        // all no proof of its current key. A public room still reads it.
        let mallory = SigningKey::generate(&mut OsRng);
        let forged = SignedRecord::channel_presence_v1_at(
            "mallory", None, room.channel_id, room.pubkey, &current, false, channel::presence_epoch(now), false, &[9; 32], &mallory, now,
        );
        let (latest, admits) = merge_channel_presence_blobs(&[blob(&forged)], &room.channel_id, &secrets, true, now);
        assert!(latest.is_empty(), "not read in a private room");
        assert!(!admits.contains(&pk(&mallory)), "and never as holding the current key");
        let (latest, _) = merge_channel_presence_blobs(&[blob(&forged)], &room.channel_id, &secrets, false, now);
        assert!(latest.contains_key(&pk(&mallory)), "the public shape, in a public room");

        // A newer v1 leave beats an older v2 announce: the merge is by member.
        let ada_left = SignedRecord::channel_presence_v1_at(
            "ada", None, room.channel_id, room.pubkey, &current, true, channel::presence_epoch(now), true, &[1; 32], &ada, now + 5,
        );
        let (latest, _) =
            merge_channel_presence_blobs(&[blob(&ada_v2), blob(&ada_left)], &room.channel_id, &secrets, true, now + 5);
        assert!(latest[&pk(&ada)].departed);
    }

    fn temp_db(name: &str) -> (std::path::PathBuf, Database) {
        let path = std::env::temp_dir().join(format!(
            "ember-membership-v2-{name}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        (path.clone(), Database::open_at(&path).expect("open db"))
    }

    fn identity(seed: [u8; 32]) -> crate::storage::identity::NodeIdentity {
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        crate::storage::identity::NodeIdentity {
            kad_id: [0; 16],
            user_hash: [0; 16],
            udp_key_seed: 0,
            ember_hash: channel::channel_id_from_pubkey(&public),
            ed25519_secret_key: seed,
            ed25519_public_key: public,
            noise_private_key: [0; 32],
            noise_public_key: [0; 32],
            intro_secret: [0; crate::network::ember::crypto::INTRO_SECRET_LEN],
        }
    }

    fn remove(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A room at epoch 4 whose owner signs with `OWNER_SEED`, and the secret
    /// of each epoch.
    const OWNER_SEED: [u8; 32] = [0x0Au8; 32];
    const SECRETS: [[u8; 32]; 5] = [[0x30; 32], [0x31; 32], [0x32; 32], [0x33; 32], [0x34; 32]];

    /// A member's device in `room`: joined with epoch 0's secret, told of
    /// epoch 4 by the owner's snapshot, holding `held` besides.
    fn member_device(name: &str, room: &ChannelIdentity, held: &[i64]) -> (std::path::PathBuf, Database) {
        let (path, db) = temp_db(name);
        let id_hex = hex::encode(room.channel_id);
        let owner_pub = SigningKey::from_bytes(&OWNER_SEED).verifying_key().to_bytes();
        db.insert_channel(&id_hex, &hex::encode(room.pubkey), "Den", "private", false, None, Some(&SECRETS[0]))
            .expect("insert channel");
        db.apply_channel_moderation(&id_hex, "", "", 1_000, &[], &[], Some(&owner_pub), None, None, Some(4), None, None)
            .expect("owner known");
        for &epoch in held {
            db.insert_channel_key_epoch(&id_hex, epoch, &SECRETS[epoch as usize]).expect("held epoch");
        }
        (path, db)
    }

    /// The owner's copy of `epoch` for `member`, every form it publishes,
    /// as blobs: what a rotation, a renewal and an unban's re-seal all send.
    fn owner_publishes(room: &ChannelIdentity, member: &[u8; 32], epoch: i64, key: &[u8; 32]) -> Vec<SignedRecord> {
        let wrap = channel::derive_channel_epoch_secret(&OWNER_SEED, member, &room.channel_id, epoch).unwrap();
        let blind = channel::epoch_blind(&OWNER_SEED, member, &room.channel_id).unwrap();
        let sealed = channel::seal_channel_key_epoch(&wrap, &room.channel_id, epoch, key);
        SignedRecord::channel_key_epoch_forms(
            room.channel_id, room.pubkey, member, false, epoch, &blind, &sealed, &room.signing_key,
        )
    }

    fn v2_only(records: &[SignedRecord]) -> Vec<Vec<u8>> {
        records
            .iter()
            .filter(|r| r.channel.as_ref().unwrap().flags & crate::network::ember::dht::publish::CHANNEL_FLAG_BLINDED != 0)
            .map(blob)
            .collect()
    }

    /// A member several epochs behind computes its own v2 record's key for
    /// the room's current epoch from the owner's key alone and opens it, then
    /// looks up the newest epoch it still misses; a v1 record is still read.
    #[test]
    fn a_member_several_epochs_behind_finds_its_current_v2_record_directly() {
        let room = ChannelIdentity::generate();
        let id_hex = hex::encode(room.channel_id);
        let ada = identity([0x0Bu8; 32]);
        let (path, db) = member_device("behind", &room, &[]);
        let lookup = |db: &Database| {
            let ch = db.get_channel(&id_hex).unwrap().unwrap();
            channel_epoch_lookup(db, &ada.ed25519_secret_key, &ada.ed25519_public_key, &ch, &room.channel_id)
        };

        let published = owner_publishes(&room, &ada.ed25519_public_key, 4, &SECRETS[4]);
        let (target, keys) = lookup(&db).expect("epoch 4 is missing");
        assert_eq!(target, 4);
        assert_eq!(keys, published.iter().map(|r| r.keyword_hash).collect::<Vec<_>>(), "v2 key, then v1");
        assert_eq!(
            ingest_channel_epoch_records(&db, &ada, room.channel_id, 4, &v2_only(&published)),
            ChannelEpochIngest::Rekeyed
        );
        assert_eq!(db.load_channel_key_epochs(&id_hex).unwrap()[0], (4, SECRETS[4]));

        // The epochs in between, newest first, each under its own key.
        let (target, keys) = lookup(&db).unwrap();
        assert_eq!(target, 3);
        let three = owner_publishes(&room, &ada.ed25519_public_key, 3, &SECRETS[3]);
        assert_eq!(keys[0], three[0].keyword_hash);
        // v1 alone, as a 1.7.4 owner or storer leaves it, is still read.
        assert_eq!(
            ingest_channel_epoch_records(&db, &ada, room.channel_id, 3, &[blob(&three[1])]),
            ChannelEpochIngest::Rekeyed
        );
        assert_eq!(lookup(&db).unwrap().0, 2);
        for epoch in [2, 1] {
            let records = owner_publishes(&room, &ada.ed25519_public_key, epoch, &SECRETS[epoch as usize]);
            assert_eq!(
                ingest_channel_epoch_records(&db, &ada, room.channel_id, epoch, &v2_only(&records)),
                ChannelEpochIngest::Rekeyed
            );
        }
        assert_eq!(lookup(&db), None, "nothing left to look up");

        drop(db);
        remove(&path);
    }

    /// A member whose copy of a rotation was never published opens the
    /// owner's renewal, and one unbanned after rotations it was left out of
    /// opens the re-seal: neither needs any epoch it does not hold.
    #[test]
    fn a_missed_rotation_and_an_unban_after_several_rotations_both_open_the_current_record() {
        let room = ChannelIdentity::generate();
        // Bob held epoch 2; the publish of epoch 3 to him failed, and epoch
        // 4's arrives as the owner's renewal.
        let bob = identity([0x0Cu8; 32]);
        let (bob_path, bob_db) = member_device("missed", &room, &[1, 2]);
        // Cy was banned before epoch 2, so 2 and 3 were sealed to everyone but
        // him; the unban re-seals epoch 4.
        let cy = identity([0x0Du8; 32]);
        let (cy_path, cy_db) = member_device("unbanned", &room, &[1]);

        for (member, db) in [(&bob, &bob_db), (&cy, &cy_db)] {
            let ch = db.get_channel(&hex::encode(room.channel_id)).unwrap().unwrap();
            let (target, keys) = channel_epoch_lookup(
                db,
                &member.ed25519_secret_key,
                &member.ed25519_public_key,
                &ch,
                &room.channel_id,
            )
            .unwrap();
            assert_eq!(target, 4);
            let current = owner_publishes(&room, &member.ed25519_public_key, 4, &SECRETS[4]);
            assert_eq!(keys[0], current[0].keyword_hash);
            assert_eq!(
                ingest_channel_epoch_records(db, member, room.channel_id, 4, &v2_only(&current)),
                ChannelEpochIngest::Rekeyed
            );
        }

        drop(bob_db);
        drop(cy_db);
        remove(&bob_path);
        remove(&cy_path);
    }

    /// Of copies signed the same second, v2 is the one taken; a v2 record is
    /// read only in its own slot, under the key a storer recomputes; and
    /// another member's record is not ours.
    #[test]
    fn epoch_records_read_v2_first_and_only_where_they_are_filed() {
        let room = ChannelIdentity::generate();
        let ada = identity([0x0Bu8; 32]);
        let (path, db) = member_device("v2-first", &room, &[]);
        let record = |epoch: i64, key: &[u8; 32], blinded: bool, at: i64| {
            let wrap = channel::derive_channel_epoch_secret(
                &OWNER_SEED,
                &ada.ed25519_public_key,
                &room.channel_id,
                epoch,
            )
            .unwrap();
            let blind = channel::epoch_blind(&OWNER_SEED, &ada.ed25519_public_key, &room.channel_id).unwrap();
            let sealed = channel::seal_channel_key_epoch(&wrap, &room.channel_id, epoch, key);
            SignedRecord::channel_key_epoch_at(
                room.channel_id,
                room.pubkey,
                &ada.ed25519_public_key,
                blinded.then_some(&blind),
                epoch,
                &sealed,
                &room.signing_key,
                at,
            )
        };

        // Signed by the room key and sealed to Ada, but filed under epoch 3's
        // key: refused by the parse, as by a storer.
        let genuine = record(4, &SECRETS[4], true, 2_000);
        let mut misfiled = genuine.clone();
        misfiled.keyword_hash = record(3, &SECRETS[4], true, 2_000).keyword_hash;
        misfiled.data[1..17].copy_from_slice(&misfiled.keyword_hash);
        misfiled.signature = crate::network::ember::crypto::sign(&room.signing_key, &misfiled.data);
        assert!(!misfiled.channel_store_ok());
        assert_eq!(
            ingest_channel_epoch_records(&db, &ada, room.channel_id, 4, &[blob(&misfiled)]),
            ChannelEpochIngest::Nothing
        );

        // The v1 copy signed the same second carries another key: v2 wins.
        let decoy = [0x99u8; 32];
        assert_eq!(
            ingest_channel_epoch_records(
                &db,
                &ada,
                room.channel_id,
                4,
                &[blob(&record(4, &decoy, false, 2_000)), blob(&genuine)],
            ),
            ChannelEpochIngest::Rekeyed
        );
        assert_eq!(db.load_channel_key_epochs(&hex::encode(room.channel_id)).unwrap()[0], (4, SECRETS[4]));

        // A v2 record sealed to someone else's slot is not ours.
        let other = identity([0x0Eu8; 32]);
        let (other_path, other_db) = member_device("v2-other", &room, &[]);
        assert_eq!(
            ingest_channel_epoch_records(&other_db, &other, room.channel_id, 4, &[blob(&genuine)]),
            ChannelEpochIngest::Nothing
        );

        drop(db);
        drop(other_db);
        remove(&path);
        remove(&other_path);
    }
}

#[cfg(test)]
mod channel_settings_ingest_tests {
    use super::{
        ingest_channel_settings_records, own_channel_settings, owner_publishes_channel_settings,
        private_room_admission,
    };
    use crate::network::ember::channel::{
        chat_author_joins_gossip_roster, ChannelIdentity, OpenedUnder, RosterAdmission,
        CHANNEL_MSG_TTL_DEFAULT,
    };
    use crate::network::ember::dht::publish::SignedRecord;
    use crate::storage::database::Database;

    fn blob(ident: &ChannelIdentity, commitments: &[(i64, [u8; 32])], at: i64) -> Vec<u8> {
        blob_admitting(ident, commitments, 0, at)
    }

    fn blob_admitting(
        ident: &ChannelIdentity,
        commitments: &[(i64, [u8; 32])],
        admission: u8,
        at: i64,
    ) -> Vec<u8> {
        let record = SignedRecord::channel_settings_at(
            commitments,
            admission,
            ident.channel_id,
            ident.pubkey,
            true,
            &ident.signing_key,
            at,
        )
        .expect("fits");
        let mut blob = record.data.clone();
        blob.extend_from_slice(&record.signature);
        blob
    }

    /// The newest record among those found is held, a later lookup that finds
    /// older ones or none changes nothing, and a record from any key but the
    /// room's is never held.
    #[test]
    fn the_newest_settings_record_is_held_and_absence_changes_nothing() {
        let path = std::env::temp_dir().join(format!(
            "ember-room-settings-ingest-{}-{}.db",
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
        db.insert_channel(&id_hex, &hex::encode(ident.pubkey), "Den", "private", false, None, Some(&[3u8; 32]))
            .expect("insert channel");

        let one = [(1, [0x01; 32])];
        let two = [(2, [0x02; 32]), (1, [0x01; 32])];
        assert!(ingest_channel_settings_records(
            &db,
            ident.channel_id,
            &[blob(&ident, &one, 1_000), blob(&ident, &two, 1_001), b"junk".to_vec()],
        ));
        assert_eq!(db.channel_settings(&id_hex).unwrap().unwrap().key_commitments, two.to_vec());

        assert!(!ingest_channel_settings_records(&db, ident.channel_id, &[blob(&ident, &one, 1_000)]));
        assert!(!ingest_channel_settings_records(&db, ident.channel_id, &[]));
        let held = db.channel_settings(&id_hex).unwrap().unwrap();
        assert_eq!((held.signed_at, held.key_commitments), (1_001, two.to_vec()));

        // Another room's record, even one newer, is not this room's.
        let other = ChannelIdentity::generate();
        assert!(!ingest_channel_settings_records(&db, ident.channel_id, &[blob(&other, &one, 2_000)]));
        assert_eq!(db.channel_settings(&id_hex).unwrap().unwrap().signed_at, 1_001);

        let three = [(3, [0x03; 32]), (2, [0x02; 32]), (1, [0x01; 32])];
        assert!(ingest_channel_settings_records(&db, ident.channel_id, &[blob(&ident, &three, 1_002)]));
        assert_eq!(db.channel_settings(&id_hex).unwrap().unwrap().key_commitments, three.to_vec());

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    fn temp_db(name: &str) -> (std::path::PathBuf, Database) {
        let path = std::env::temp_dir().join(format!(
            "ember-room-settings-{name}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        (path, db)
    }

    fn remove(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// A member holds a private room's chat lines to the newest settings
    /// record it holds: none held is the rule before 1.7.5, a held tag 2 of 1
    /// or any value it does not know closes chat admission, and a newer record
    /// without it opens it again. The owner applies its own rule with nothing
    /// held.
    #[test]
    fn the_held_settings_record_decides_whether_a_chat_line_admits() {
        let (path, db) = temp_db("admission");
        let ident = ChannelIdentity::generate();
        let id_hex = hex::encode(ident.channel_id);
        db.insert_channel(&id_hex, &hex::encode(ident.pubkey), "Den", "private", false, None, Some(&[3u8; 32]))
            .expect("insert channel");
        let now = 1_800_000_000;
        let fresh_line = |admission| {
            chat_author_joins_gossip_roster(
                true,
                admission,
                OpenedUnder::Current,
                CHANNEL_MSG_TTL_DEFAULT,
                now,
                now,
            )
        };

        assert_eq!(private_room_admission(&db, &id_hex, false), RosterAdmission::Open);
        assert!(fresh_line(private_room_admission(&db, &id_hex, false)), "nothing held: unchanged");

        assert!(ingest_channel_settings_records(&db, ident.channel_id, &[blob_admitting(&ident, &[], 1, 1_000)]));
        assert_eq!(db.channel_settings(&id_hex).unwrap().unwrap().admission, 1);
        assert_eq!(private_room_admission(&db, &id_hex, false), RosterAdmission::KeyProven);
        assert!(!fresh_line(private_room_admission(&db, &id_hex, false)));

        assert!(ingest_channel_settings_records(&db, ident.channel_id, &[blob_admitting(&ident, &[], 0xC8, 1_001)]));
        assert_eq!(db.channel_settings(&id_hex).unwrap().unwrap().admission, 0xC8);
        assert_eq!(
            private_room_admission(&db, &id_hex, false),
            RosterAdmission::KeyProven,
            "a value this build does not know reads as the strict rule"
        );

        assert!(ingest_channel_settings_records(&db, ident.channel_id, &[blob(&ident, &[], 1_002)]));
        assert_eq!(private_room_admission(&db, &id_hex, false), RosterAdmission::Open, "the owner left it out");
        assert!(!ingest_channel_settings_records(&db, ident.channel_id, &[]));
        assert_eq!(private_room_admission(&db, &id_hex, false), RosterAdmission::Open, "absence is no reset");

        let owned = ChannelIdentity::generate();
        let owned_hex = hex::encode(owned.channel_id);
        db.insert_channel(&owned_hex, &hex::encode(owned.pubkey), "Ours", "private", true, Some(&[4u8; 32]), Some(&[5u8; 32]))
            .expect("insert owned channel");
        assert_eq!(db.channel_settings(&owned_hex).unwrap(), None);
        assert_eq!(private_room_admission(&db, &owned_hex, true), RosterAdmission::OWNED_PRIVATE_ROOM);

        drop(db);
        remove(&path);
    }

    /// Tag 2 gives every private room something to state, so an owner
    /// publishes for one that has never rotated, with no commitments; a
    /// public room still publishes nothing.
    #[test]
    fn an_owner_publishes_tag_2_for_a_room_that_never_rotated_and_nothing_for_a_public_one() {
        let (path, db) = temp_db("owner-publish");
        let private = ChannelIdentity::generate();
        let private_hex = hex::encode(private.channel_id);
        db.insert_channel(&private_hex, &hex::encode(private.pubkey), "Ours", "private", true, Some(&[6u8; 32]), Some(&[7u8; 32]))
            .expect("insert private channel");
        let public = ChannelIdentity::generate();
        let public_hex = hex::encode(public.channel_id);
        db.insert_channel(&public_hex, &hex::encode(public.pubkey), "Open", "public", true, Some(&[8u8; 32]), None)
            .expect("insert public channel");

        let row = db.get_channel(&private_hex).unwrap().unwrap();
        assert_eq!(row.key_epoch, 0, "never rotated");
        assert!(owner_publishes_channel_settings(&row));
        let epochs = db.load_channel_key_epochs(&private_hex).unwrap();
        assert!(epochs.iter().all(|(epoch, _)| *epoch == 0));
        let (commitments, admission) = own_channel_settings(&private.channel_id, &epochs);
        assert!(commitments.is_empty(), "epoch 0 has nothing to commit to");
        assert_eq!(admission, RosterAdmission::KeyProven);
        let record = SignedRecord::channel_settings_at(
            &commitments,
            admission.setting(),
            private.channel_id,
            private.pubkey,
            true,
            &private.signing_key,
            1_000,
        )
        .unwrap();
        let mut published = record.data.clone();
        published.extend_from_slice(&record.signature);
        let parsed = SignedRecord::parse_channel_settings(&published, &private.channel_id).unwrap();
        assert_eq!(parsed.admission, 1);
        assert!(parsed.key_commitments.is_empty());

        let rotated = [(2, [0x22; 32]), (1, [0x11; 32]), (0, [7u8; 32])];
        let (commitments, _) = own_channel_settings(&private.channel_id, &rotated);
        assert_eq!(commitments.iter().map(|(epoch, _)| *epoch).collect::<Vec<_>>(), vec![2, 1]);

        assert!(!owner_publishes_channel_settings(&db.get_channel(&public_hex).unwrap().unwrap()));
        let joined = ChannelIdentity::generate();
        let joined_hex = hex::encode(joined.channel_id);
        db.insert_channel(&joined_hex, &hex::encode(joined.pubkey), "Theirs", "private", false, None, Some(&[9u8; 32]))
            .expect("insert joined channel");
        assert!(
            !owner_publishes_channel_settings(&db.get_channel(&joined_hex).unwrap().unwrap()),
            "only the owner speaks for a room"
        );

        drop(db);
        remove(&path);
    }
}

#[cfg(test)]
mod channel_settings_schedule_tests {
    use super::{
        channel_settings_publish_plan, channel_settings_read_due, note_owned_rooms_read_ended,
        owned_rooms_publish_gate, owned_rooms_publish_waits, owned_rooms_read_asked_at,
        owned_rooms_read_still_wanted, owned_rooms_read_test_lock, owner_publishes_channel_settings,
        owner_republish_held_back, read_owned_channel_settings, reset_owned_rooms_read_times,
        rearm_abandoned_settings_lookup, settings_fetch_rides_pass, settings_lookup_backoff_allows,
        settings_owed_after_pass, ChannelSettingsPublished, OwnedChannelSettingsRead, RestoringRoom,
        RotatingRoom, SettingsLookupBackoff, CHANNEL_SETTINGS_CONFIRM_SECS,
        CHANNEL_SETTINGS_HELD_BACK_SECS, OWNED_ROOMS_READ_FRESH_SECS, OWNED_ROOMS_READ_WAIT_SECS,
        SETTINGS_LOOKUP_BACKOFF_MAX_SECS,
    };
    use crate::network::ember::channel::{content_key, key_commitment, ChannelIdentity, MODERATION_REPUBLISH_SECS};
    use crate::network::ember::dht::publish::SignedRecord;
    use crate::storage::database::{Database, HeldChannelSettings};
    use std::collections::{HashMap, HashSet};

    fn temp_db(name: &str) -> (std::path::PathBuf, Database) {
        let path = std::env::temp_dir().join(format!(
            "ember-settings-schedule-{name}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        (path, db)
    }

    fn remove(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    fn owned_room(db: &Database, visibility: &str) -> ChannelIdentity {
        let ident = ChannelIdentity::generate();
        db.insert_channel(
            &hex::encode(ident.channel_id),
            &hex::encode(ident.pubkey),
            "Ours",
            visibility,
            true,
            Some(&ident.seed()),
            (visibility == "private").then_some(&[7u8; 32]),
        )
        .expect("insert owned channel");
        ident
    }

    fn held(commitments: &[(i64, [u8; 32])]) -> HeldChannelSettings {
        HeldChannelSettings {
            signed_at: 1,
            signature: [1; 64],
            key_commitments: commitments.to_vec(),
            admission: 1,
        }
    }

    /// [`read_owned_channel_settings`] at the room's key generation as it
    /// stands, read again when another test's key write moves the slot the
    /// room shares under the read.
    fn read_now(
        db: &Database,
        ident: &ChannelIdentity,
        last: Option<&[(i64, [u8; 32])]>,
        schedule_due: bool,
        now: i64,
    ) -> OwnedChannelSettingsRead {
        let id_hex = hex::encode(ident.channel_id);
        for _ in 0..8 {
            let generation = db.channel_key_generation(&id_hex);
            let read = read_owned_channel_settings(db, ident.channel_id, generation, last, schedule_due, now);
            if !matches!(read, OwnedChannelSettingsRead::HeldBack) || db.channel_key_generation(&id_hex) == generation {
                return read;
            }
        }
        panic!("the key generation kept moving");
    }

    /// The settings lookup rides every third moderation pass, the first
    /// included, and only for a private room this device does not own.
    #[test]
    fn settings_ride_every_third_moderation_pass_of_a_room_this_device_reads() {
        let (path, db) = temp_db("rides");
        let member = ChannelIdentity::generate();
        let member_hex = hex::encode(member.channel_id);
        db.insert_channel(&member_hex, &hex::encode(member.pubkey), "Den", "private", false, None, Some(&[3u8; 32]))
            .unwrap();
        let public = ChannelIdentity::generate();
        let public_hex = hex::encode(public.channel_id);
        db.insert_channel(&public_hex, &hex::encode(public.pubkey), "Hall", "public", false, None, None)
            .unwrap();
        let owned = owned_room(&db, "private");
        let row = |id: &str| db.get_channel(id).unwrap().unwrap();

        let rides: Vec<u64> = (0..9).filter(|pass| settings_fetch_rides_pass(*pass, &row(&member_hex))).collect();
        assert_eq!(rides, vec![0, 3, 6]);
        for pass in 0..9 {
            assert!(!settings_fetch_rides_pass(pass, &row(&public_hex)), "a public room states nothing");
            assert!(
                !settings_fetch_rides_pass(pass, &row(&hex::encode(owned.channel_id))),
                "an owner applies its own"
            );
        }

        drop(db);
        remove(&path);
    }

    /// A moderation pass asks for the settings record at once when its
    /// snapshot named a newer epoch, and on every pass after while this device
    /// is behind and holds no commitment to the epoch it is behind on.
    #[test]
    fn a_pass_asks_for_settings_at_once_while_the_announced_epoch_is_uncommitted() {
        let (path, db) = temp_db("owed");
        let ident = ChannelIdentity::generate();
        let id_hex = hex::encode(ident.channel_id);
        db.insert_channel(&id_hex, &hex::encode(ident.pubkey), "Den", "private", false, None, Some(&[3u8; 32]))
            .unwrap();
        db.insert_channel_key_epoch(&id_hex, 1, &[1u8; 32]).unwrap();
        let row = || db.get_channel(&id_hex).unwrap().unwrap();
        let committed = |epochs: &[i64]| held(&epochs.iter().map(|epoch| (*epoch, [*epoch as u8; 32])).collect::<Vec<_>>());

        assert!(!settings_owed_after_pass(Some(0), &row(), None), "not behind, nothing new");

        assert!(db
            .apply_channel_moderation(&id_hex, "", "", 10, &[], &[], None, None, None, Some(3), None, None)
            .unwrap());
        assert!(settings_owed_after_pass(Some(0), &row(), None), "the snapshot named a newer epoch");
        assert!(settings_owed_after_pass(Some(3), &row(), None), "behind, with no record held");
        assert!(settings_owed_after_pass(Some(3), &row(), Some(&committed(&[2, 1]))), "behind, uncommitted");
        assert!(!settings_owed_after_pass(Some(3), &row(), Some(&committed(&[3, 2]))), "the commitment is held");
        assert!(!settings_owed_after_pass(None, &row(), Some(&committed(&[3]))));

        db.insert_channel_key_epoch(&id_hex, 3, &[3u8; 32]).unwrap();
        assert!(!settings_owed_after_pass(Some(3), &row(), Some(&committed(&[2, 1]))), "caught up");

        let owned = owned_room(&db, "private");
        let owned_row = db.get_channel(&hex::encode(owned.channel_id)).unwrap().unwrap();
        assert!(!settings_owed_after_pass(Some(-1), &owned_row, None), "an owner fetches none");

        drop(db);
        remove(&path);
    }

    /// A lookup given up on before it finished leaves its room owed one, so
    /// the next settings pass asks again.
    #[test]
    fn an_abandoned_settings_lookup_is_owed_again() {
        let room = [0x5Au8; 16];
        let mut searches = HashMap::from([(7u32, room), (8u32, [0x5Bu8; 16])]);
        let mut owed = HashSet::new();
        rearm_abandoned_settings_lookup(&mut searches, &mut owed, 7);
        assert!(owed.contains(&room));
        assert!(!searches.contains_key(&7));
        assert!(searches.contains_key(&8), "other lookups stay");
        rearm_abandoned_settings_lookup(&mut searches, &mut owed, 99);
        assert_eq!(owed.len(), 1, "an unknown search owes nothing");
    }

    /// A room owed lookups after its passes gets the first at once and the
    /// next a pass later, then each twice as long after the one before, up to
    /// the cap; a move of its epochs or a record landing starts over.
    #[test]
    fn lookups_owed_after_passes_back_off_while_nothing_answers() {
        let pass = crate::network::ember::channel::MODERATION_FETCH_SECS;
        let room = [0x61u8; 16];
        let mut backoff = SettingsLookupBackoff::default();
        let now = 1_800_000_000;
        // A pass every five minutes for two days, each a few seconds late.
        let asked: Vec<i64> = (0..576)
            .map(|n| now + n * pass + n % 7)
            .filter(|at| settings_lookup_backoff_allows(&mut backoff, room, (3, 1), *at))
            .collect();
        let gaps: Vec<i64> = asked.windows(2).map(|w| (w[1] - w[0] + pass / 2) / pass * pass).collect();
        assert_eq!(&gaps[..4], &[pass, 2 * pass, 4 * pass, 8 * pass], "{asked:?}");
        assert!(gaps.windows(2).all(|w| w[1] >= w[0]), "never sooner than the last wait: {gaps:?}");
        let last = *gaps.last().unwrap();
        assert!(
            (SETTINGS_LOOKUP_BACKOFF_MAX_SECS - pass..=SETTINGS_LOOKUP_BACKOFF_MAX_SECS + pass).contains(&last),
            "capped at six hours: {gaps:?}"
        );

        let later = *asked.last().unwrap() + pass;
        assert!(!settings_lookup_backoff_allows(&mut backoff, room, (3, 1), later));
        assert!(settings_lookup_backoff_allows(&mut backoff, room, (4, 1), later), "a newer epoch announced");
        assert!(!settings_lookup_backoff_allows(&mut backoff, room, (4, 1), later + 1));
        backoff.forget(&room);
        assert!(settings_lookup_backoff_allows(&mut backoff, room, (4, 1), later + 2), "a record landed");
        assert!(
            settings_lookup_backoff_allows(&mut backoff, [0x62u8; 16], (4, 1), later + 2),
            "each room on its own"
        );

        backoff.retain_rooms(|id| *id == room);
        assert!(!settings_lookup_backoff_allows(&mut backoff, room, (4, 1), later + 3), "a room kept keeps its wait");
        assert_eq!(backoff.0.len(), 1, "a room left is dropped");
    }

    /// The owned-rooms list goes out only on a recent look at the network's
    /// copy. Without one it waits, for a look that then ends however it
    /// ends, or for a bounded time when none does.
    #[test]
    fn the_owned_rooms_list_goes_out_only_after_a_recent_look() {
        let now = 1_800_000_000;
        assert!(owned_rooms_publish_waits(0, 0, now), "no look this launch");
        assert!(!owned_rooms_publish_waits(now - 60, 0, now), "the look ahead of a scheduled publish");
        assert!(!owned_rooms_publish_waits(now - OWNED_ROOMS_READ_FRESH_SECS, 0, now));
        let stale = now - 3 * 3_600;
        assert!(owned_rooms_publish_waits(stale, 0, now), "the last look was hours ago: ask for one");
        let asked = now;
        assert!(owned_rooms_publish_waits(stale, asked, asked + 30), "the look asked for is under way");
        assert!(!owned_rooms_publish_waits(asked + 1, asked, asked + 90), "it ended, read or not");
        assert!(owned_rooms_publish_waits(stale, asked, asked + OWNED_ROOMS_READ_WAIT_SECS - 1));
        assert!(
            !owned_rooms_publish_waits(stale, asked, asked + OWNED_ROOMS_READ_WAIT_SECS),
            "a look that never comes holds it back only so long"
        );
        let long_after = asked + OWNED_ROOMS_READ_WAIT_SECS + OWNED_ROOMS_READ_FRESH_SECS;
        assert!(
            owned_rooms_publish_waits(stale, asked, long_after),
            "an ask left by a publish that never went is no ask"
        );
    }

    /// A publish that waits asks for a look once. Its ask is dropped when the
    /// list is no longer due, so a publish due hours later asks for a look of
    /// its own rather than going out on the old ask.
    #[test]
    fn a_publish_no_longer_due_drops_its_ask_for_a_look() {
        let _serial = owned_rooms_read_test_lock().blocking_lock();
        reset_owned_rooms_read_times();
        let now = 1_800_000_000;
        assert!(!owned_rooms_publish_gate(true, now), "no look this launch");
        assert_eq!(owned_rooms_read_asked_at(), now);
        assert!(!owned_rooms_publish_gate(true, now + 30));
        assert_eq!(owned_rooms_read_asked_at(), now, "asked once");

        // The room that made the list due is deleted within the wait.
        assert!(!owned_rooms_publish_gate(false, now + 60));
        assert_eq!(owned_rooms_read_asked_at(), 0);
        let later = now + 3 * 3_600;
        assert!(!owned_rooms_publish_gate(true, later), "waits on a look of its own");
        assert_eq!(owned_rooms_read_asked_at(), later);

        // An ask left behind all the same is too old to let a publish go.
        reset_owned_rooms_read_times();
        assert!(!owned_rooms_publish_gate(true, now));
        let much_later = now + 5 * 3_600;
        assert!(!owned_rooms_publish_gate(true, much_later));
        assert_eq!(owned_rooms_read_asked_at(), much_later, "asked again");
        assert!(owned_rooms_publish_gate(true, much_later + OWNED_ROOMS_READ_WAIT_SECS));
        assert_eq!(owned_rooms_read_asked_at(), 0, "gone out");
        reset_owned_rooms_read_times();
    }

    /// The read loop, woken by a publish, looks only when no recent look has
    /// ended since: one already under way when the publish asked serves it.
    #[test]
    fn a_look_under_way_when_a_publish_asks_serves_it() {
        let _serial = owned_rooms_read_test_lock().blocking_lock();
        reset_owned_rooms_read_times();
        let now = chrono::Utc::now().timestamp();
        assert!(!owned_rooms_publish_gate(true, now));
        assert!(owned_rooms_read_still_wanted(now));
        note_owned_rooms_read_ended(now - 120);
        assert!(!owned_rooms_read_still_wanted(now + 1));
        assert!(owned_rooms_publish_gate(true, now + 1));
        assert!(owned_rooms_read_still_wanted(now + OWNED_ROOMS_READ_FRESH_SECS), "that look has gone stale");
        reset_owned_rooms_read_times();
    }

    /// The owner loop signs nothing for a room whose rotation has stored its
    /// key and not committed yet, nor for one a recovery is putting back.
    #[test]
    fn the_owner_loop_leaves_a_rotating_room_alone() {
        let (path, db) = temp_db("rotating-owner");
        let ident = owned_room(&db, "private");
        let id_hex = hex::encode(ident.channel_id);
        assert!(!owner_republish_held_back(&db, &id_hex));

        let rotating = RotatingRoom::begin(&id_hex);
        db.insert_channel_key_epoch(&id_hex, 1, &[0x11; 32]).unwrap();
        assert!(owner_republish_held_back(&db, &id_hex), "the new epoch may yet be taken back");
        db.rollback_channel_key_epoch(&id_hex, 1).unwrap();
        drop(rotating);
        assert!(!owner_republish_held_back(&db, &id_hex), "once the rotation is over");

        let restoring = RestoringRoom::begin(&id_hex);
        assert!(owner_republish_held_back(&db, &id_hex));
        drop(restoring);
        assert!(!owner_republish_held_back(&db, &id_hex));

        drop(db);
        remove(&path);
    }

    /// The owner reads a room's keys only when they have moved or the room is
    /// due, publishes when the commitments differ from those last published,
    /// once more within the confirm interval, then on the snapshot's cadence;
    /// a public room publishes nothing, and a room the gates hold back reads
    /// nothing either.
    #[test]
    fn the_owner_publishes_on_a_change_then_confirms_then_republishes() {
        let (path, db) = temp_db("publish");
        let ident = owned_room(&db, "private");
        let id_hex = hex::encode(ident.channel_id);
        let now = 1_800_000_000;
        let commit = |epoch: i64, secret: &[u8; 32]| (epoch, key_commitment(&ident.channel_id, epoch, &content_key(secret)));

        assert!(channel_settings_read_due(None, 0, now), "nothing published this launch");
        let OwnedChannelSettingsRead::Read {
            key_commitments,
            publish: Some(publish),
        } = read_now(&db, &ident, None, true, now)
        else {
            panic!("a never-rotated private room publishes");
        };
        let (record, held_copy, next_in) = *publish;
        assert!(key_commitments.is_empty());
        assert_eq!(next_in, MODERATION_REPUBLISH_SECS);
        assert_eq!(held_copy.admission, 1);
        let mut blob = record.data.clone();
        blob.extend_from_slice(&record.signature);
        assert_eq!(SignedRecord::parse_channel_settings(&blob, &ident.channel_id).unwrap().admission, 1);
        assert_eq!(db.channel_settings(&id_hex).unwrap(), None, "nothing is held until the publish starts");

        let generation = db.channel_key_generation(&id_hex);
        let published = ChannelSettingsPublished {
            generation,
            key_commitments: Some(key_commitments),
            due_at: now + next_in,
            verdict: None,
        };
        assert!(!channel_settings_read_due(Some(&published), generation, now + 60), "settled: no read");
        assert!(channel_settings_read_due(Some(&published), generation, now + next_in), "due");

        db.insert_channel_key_epoch(&id_hex, 1, &[0x11; 32]).unwrap();
        let moved = db.channel_key_generation(&id_hex);
        assert_ne!(moved, generation, "a rotation moves the room's key generation");
        assert!(channel_settings_read_due(Some(&published), moved, now + 60));
        let OwnedChannelSettingsRead::Read {
            key_commitments,
            publish: Some(publish),
        } = read_now(&db, &ident, Some(&[][..]), false, now + 60)
        else {
            panic!("changed commitments publish at once");
        };
        let (_, _, next_in) = *publish;
        assert_eq!(key_commitments, vec![commit(1, &[0x11; 32])]);
        assert_eq!(next_in, CHANNEL_SETTINGS_CONFIRM_SECS);

        let OwnedChannelSettingsRead::Read { publish: None, .. } =
            read_now(&db, &ident, Some(key_commitments.as_slice()), false, now + 120)
        else {
            panic!("unchanged and not due: nothing goes out");
        };
        let current = key_commitments.as_slice();
        assert_eq!(
            channel_settings_publish_plan(Some(current), None, current, true),
            Some(MODERATION_REPUBLISH_SECS),
            "the confirm, and every republish after it"
        );
        assert_eq!(channel_settings_publish_plan(Some(current), None, current, false), None);
        assert_eq!(
            channel_settings_publish_plan(None, Some(current), current, false),
            Some(MODERATION_REPUBLISH_SECS),
            "the first of a launch, as held"
        );
        assert_eq!(
            channel_settings_publish_plan(None, Some(&[][..]), current, false),
            Some(CHANNEL_SETTINGS_CONFIRM_SECS),
            "the first of a launch after a rotation the held copy predates is confirmed"
        );
        assert_eq!(channel_settings_publish_plan(None, None, current, false), Some(CHANNEL_SETTINGS_CONFIRM_SECS));
        assert_eq!(channel_settings_publish_plan(None, None, &[], false), Some(MODERATION_REPUBLISH_SECS));

        {
            let _restoring = RestoringRoom::begin(&id_hex);
            assert!(matches!(read_now(&db, &ident, None, true, now), OwnedChannelSettingsRead::HeldBack));
        }

        let public = owned_room(&db, "public");
        assert!(!owner_publishes_channel_settings(
            &db.get_channel(&hex::encode(public.channel_id)).unwrap().unwrap()
        ));

        drop(db);
        remove(&path);
    }

    /// A rotation taken back and minted again under the same number leaves
    /// `key_epoch` where it was, but not the commitment: the owner publishes
    /// the new one on the next pass rather than leaving the old one out for
    /// hours.
    #[test]
    fn a_rotation_taken_back_and_minted_again_under_the_same_epoch_publishes_again() {
        let (path, db) = temp_db("rerotate");
        let ident = owned_room(&db, "private");
        let id_hex = hex::encode(ident.channel_id);
        let now = 1_800_000_000;

        db.insert_channel_key_epoch(&id_hex, 1, &[0x11; 32]).unwrap();
        let OwnedChannelSettingsRead::Read { key_commitments: first, .. } = read_now(&db, &ident, None, true, now)
        else {
            panic!("readable");
        };
        let generation = db.channel_key_generation(&id_hex);

        db.rollback_channel_key_epoch(&id_hex, 1).unwrap();
        db.insert_channel_key_epoch(&id_hex, 1, &[0x22; 32]).unwrap();
        assert_eq!(db.get_channel(&id_hex).unwrap().unwrap().key_epoch, 1, "the same epoch number");
        let published = ChannelSettingsPublished {
            generation,
            key_commitments: Some(first.clone()),
            due_at: now + MODERATION_REPUBLISH_SECS,
            verdict: None,
        };
        assert!(channel_settings_read_due(Some(&published), db.channel_key_generation(&id_hex), now + 60));
        let OwnedChannelSettingsRead::Read {
            key_commitments: second,
            publish: Some(publish),
        } = read_now(&db, &ident, Some(first.as_slice()), false, now + 60)
        else {
            panic!("a different key under the same epoch is a change");
        };
        let (_, _, next_in) = *publish;
        assert_ne!(first, second);
        assert_eq!(second[0].0, 1);
        assert_eq!(next_in, CHANNEL_SETTINGS_CONFIRM_SECS);

        drop(db);
        remove(&path);
    }

    /// While a rotation is in flight its key is stored but may yet be taken
    /// back, so nothing is signed for the room; nor is anything read under a
    /// key generation that has moved since it was sampled, which is what a
    /// rotation taken back during the read leaves. Once the rotation ends the
    /// room is read again at once: committed, its key is in the record; taken
    /// back, it never appears in one.
    #[test]
    fn an_uncommitted_rotation_never_reaches_a_published_commitment_list() {
        let (path, db) = temp_db("in-flight");
        let ident = owned_room(&db, "private");
        let id_hex = hex::encode(ident.channel_id);
        let now = 1_800_000_000;
        let commit = |epoch: i64, secret: &[u8; 32]| (epoch, key_commitment(&ident.channel_id, epoch, &content_key(secret)));
        let commitments = |read: OwnedChannelSettingsRead| match read {
            OwnedChannelSettingsRead::Read { key_commitments, .. } => key_commitments,
            _ => panic!("read"),
        };
        db.insert_channel_key_epoch(&id_hex, 1, &[0x11; 32]).unwrap();

        let aborted = RotatingRoom::begin(&id_hex);
        db.insert_channel_key_epoch(&id_hex, 2, &[0x22; 32]).unwrap();
        assert!(matches!(read_now(&db, &ident, None, true, now), OwnedChannelSettingsRead::HeldBack));
        let sampled = db.channel_key_generation(&id_hex);
        db.rollback_channel_key_epoch(&id_hex, 2).unwrap();
        let before_end = db.channel_key_generation(&id_hex);
        drop(aborted);
        let ended = db.channel_key_generation(&id_hex);
        assert_ne!(ended, before_end, "the end of a rotation has the room read again");
        assert!(
            matches!(
                read_owned_channel_settings(&db, ident.channel_id, sampled, None, true, now),
                OwnedChannelSettingsRead::HeldBack
            ),
            "a read under a generation that has moved since signs nothing"
        );
        let published = ChannelSettingsPublished {
            generation: sampled,
            key_commitments: Some(vec![commit(1, &[0x11; 32])]),
            due_at: now + CHANNEL_SETTINGS_HELD_BACK_SECS,
            verdict: None,
        };
        assert!(channel_settings_read_due(Some(&published), ended, now + 1));
        assert_eq!(commitments(read_now(&db, &ident, None, true, now)), vec![commit(1, &[0x11; 32])]);

        let committed = RotatingRoom::begin(&id_hex);
        db.insert_channel_key_epoch(&id_hex, 2, &[0x23; 32]).unwrap();
        let nested = RotatingRoom::begin(&id_hex);
        drop(nested);
        assert!(
            matches!(read_now(&db, &ident, None, true, now), OwnedChannelSettingsRead::HeldBack),
            "held back until every rotation of the room has ended"
        );
        drop(committed);
        assert_eq!(
            commitments(read_now(&db, &ident, None, true, now)),
            vec![commit(2, &[0x23; 32]), commit(1, &[0x11; 32])]
        );

        drop(db);
        remove(&path);
    }
}

#[cfg(test)]
mod pending_invite_key_tests {
    use super::{
        epochs_contradicting_commitments, ingest_channel_settings_records, run_channel_ingest,
        settle_channel_keys_in, take_offered_key_in, ChannelIngestBatch, OfferedKey, OfferedKeyOutcome,
        PendingInviteKeys, PENDING_INVITE_KEYS_MAX, PENDING_INVITE_KEY_SECS,
    };
    use crate::network::ember::channel::{content_key, key_commitment, ChannelIdentity};
    use crate::network::ember::dht::publish::{ModerationTail, SignedRecord};
    use crate::storage::database::Database;
    use crate::storage::identity::NodeIdentity;
    use std::sync::Mutex;

    const NOW: i64 = 1_800_000_000;

    fn temp_db(name: &str) -> (std::path::PathBuf, Database) {
        let path = std::env::temp_dir().join(format!(
            "ember-pending-invite-{name}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let db = Database::open_at(&path).expect("open db");
        (path, db)
    }

    fn remove(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    fn secret(epoch: i64) -> [u8; 32] {
        [0x40 + epoch as u8; 32]
    }

    /// A private room this device joined, holding `join` as its first secret.
    fn member_room(db: &Database, join: &[u8; 32]) -> ChannelIdentity {
        let ident = ChannelIdentity::generate();
        db.insert_channel(&hex::encode(ident.channel_id), &hex::encode(ident.pubkey), "Den", "private", false, None, Some(join))
            .expect("insert channel");
        ident
    }

    fn announce(db: &Database, ident: &ChannelIdentity, epoch: i64, at: i64) {
        assert!(db
            .apply_channel_moderation(&hex::encode(ident.channel_id), "", "", at, &[], &[], None, None, None, Some(epoch as u64), None, None)
            .unwrap());
    }

    /// The owner's settings record committing to the genuine key of each of
    /// `epochs`.
    fn settings_blob(ident: &ChannelIdentity, epochs: &[i64], at: i64) -> Vec<u8> {
        let commitments: Vec<(i64, [u8; 32])> = epochs
            .iter()
            .map(|epoch| (*epoch, key_commitment(&ident.channel_id, *epoch, &content_key(&secret(*epoch)))))
            .collect();
        let record =
            SignedRecord::channel_settings_at(&commitments, 1, ident.channel_id, ident.pubkey, true, &ident.signing_key, at)
                .expect("fits");
        let mut blob = record.data.clone();
        blob.extend_from_slice(&record.signature);
        blob
    }

    /// The owner's snapshot announcing `epoch`, as a lookup returns it.
    fn moderation_blob(ident: &ChannelIdentity, epoch: i64) -> Vec<u8> {
        let tail = ModerationTail {
            owner_pubkey: Some([0x0C; 32]),
            key_epoch: Some(epoch as u64),
            ..Default::default()
        };
        let record = SignedRecord::channel_moderation(
            "",
            "",
            &[],
            &[],
            &tail,
            ident.channel_id,
            ident.pubkey,
            true,
            &ident.signing_key,
        )
        .expect("fits");
        let mut blob = record.data.clone();
        blob.extend_from_slice(&record.signature);
        blob
    }

    /// A first join stores the invite's key for its epoch before any snapshot
    /// has said what the room's epoch is, and the room's settings lookup can
    /// finish first, finding a record from before the rotation to that key.
    /// The key is not judged past what the owner announced until a snapshot
    /// has been taken; once one is, the keys are judged again at once, so a
    /// crafted first join's key at an epoch past it still goes.
    #[test]
    fn a_first_joins_key_survives_a_settings_record_ingested_before_the_first_snapshot() {
        let (path, db) = temp_db("first-join");
        let seed = [0x0Bu8; 32];
        let our_pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let identity = NodeIdentity {
            kad_id: [0; 16],
            user_hash: [0; 16],
            udp_key_seed: 0,
            ember_hash: crate::network::ember::channel::channel_id_from_pubkey(&our_pk),
            ed25519_secret_key: seed,
            ed25519_public_key: our_pk,
            noise_private_key: [0; 32],
            noise_public_key: [0; 32],
            intro_secret: [0; crate::network::ember::crypto::INTRO_SECRET_LEN],
        };
        let crafted = [0x66u8; 32];

        let genuine = member_room(&db, &secret(3));
        let genuine_hex = hex::encode(genuine.channel_id);
        db.insert_channel_key_epoch(&genuine_hex, 3, &secret(3)).unwrap();
        let far = member_room(&db, &crafted);
        let far_hex = hex::encode(far.channel_id);
        db.insert_channel_key_epoch(&far_hex, 1_000, &crafted).unwrap();

        let results = run_channel_ingest(
            &db,
            &identity,
            &our_pk,
            ChannelIngestBatch {
                settings: vec![
                    (genuine.channel_id, vec![settings_blob(&genuine, &[2, 1], 1_000)]),
                    (far.channel_id, vec![settings_blob(&far, &[2, 1], 1_000)]),
                ],
                ..Default::default()
            },
        );
        assert!(results.rekeyed.is_empty(), "nothing announced yet to judge a key past");
        assert_eq!(db.load_channel_key_epochs(&genuine_hex).unwrap(), vec![(3, secret(3))]);
        assert_eq!(db.load_channel_key_epochs(&far_hex).unwrap(), vec![(1_000, crafted)]);

        let results = run_channel_ingest(
            &db,
            &identity,
            &our_pk,
            ChannelIngestBatch {
                moderation: vec![
                    (genuine.channel_id, vec![moderation_blob(&genuine, 3)], 1),
                    (far.channel_id, vec![moderation_blob(&far, 3)], 1),
                ],
                ..Default::default()
            },
        );
        assert_eq!(results.moderated.len(), 2);
        assert_eq!(results.rekeyed, vec![far.channel_id], "judged again as the first snapshot lands");
        assert_eq!(db.load_channel_key_epochs(&genuine_hex).unwrap(), vec![(3, secret(3))]);
        let genuine_row = db.get_channel(&genuine_hex).unwrap().unwrap();
        assert_eq!((genuine_row.key_epoch, genuine_row.key_epoch_wanted), (3, 3), "the genuine key stays current");
        assert!(db.load_channel_key_epochs(&far_hex).unwrap().is_empty());

        drop(db);
        remove(&path);
    }

    /// A settle judges on one read and drops on a later write, and the join's
    /// own settle can run between them, dropping the same crafted key and
    /// storing the genuine one in its slot. The later drop removes only the
    /// key it judged, so the genuine one stays. A join whose settle dropped a
    /// key reports the room's keys changed even when the key it offered waits.
    #[test]
    fn a_settle_judging_on_an_older_read_never_drops_the_key_that_replaced_it() {
        let (path, db) = temp_db("interleaved");
        let pending = Mutex::new(PendingInviteKeys::default());
        let crafted = [0x66u8; 32];
        let ident = member_room(&db, &crafted);
        let id_hex = hex::encode(ident.channel_id);
        db.insert_channel_key_epoch(&id_hex, 3, &crafted).unwrap();
        announce(&db, &ident, 3, 10);
        assert!(ingest_channel_settings_records(&db, ident.channel_id, &[settings_blob(&ident, &[3, 2], 1_000)]));
        let row = db.get_channel(&id_hex).unwrap().unwrap();
        let held = db.channel_settings(&id_hex).unwrap().unwrap();
        let judged =
            epochs_contradicting_commitments(&row, &ident.channel_id, &db.load_channel_key_epochs(&id_hex).unwrap(), &held);
        assert_eq!(judged, vec![(3, crafted)]);

        assert_eq!(
            take_offered_key_in(&db, &pending, &row, ident.channel_id, 3, &secret(3), NOW).unwrap(),
            OfferedKeyOutcome {
                key: OfferedKey::Taken,
                rekeyed: true,
            }
        );
        assert!(db.drop_channel_key_epochs(&id_hex, &judged).unwrap().is_empty());
        assert_eq!(db.load_channel_key_epochs(&id_hex).unwrap(), vec![(3, secret(3))]);

        let other = member_room(&db, &crafted);
        let other_hex = hex::encode(other.channel_id);
        db.insert_channel_key_epoch(&other_hex, 3, &crafted).unwrap();
        announce(&db, &other, 3, 10);
        assert!(ingest_channel_settings_records(&db, other.channel_id, &[settings_blob(&other, &[3, 2], 1_000)]));
        let row = db.get_channel(&other_hex).unwrap().unwrap();
        assert_eq!(
            take_offered_key_in(&db, &pending, &row, other.channel_id, 3, &[0x77; 32], NOW).unwrap(),
            OfferedKeyOutcome {
                key: OfferedKey::Held,
                rekeyed: true,
            },
            "the crafted key went though the offered one waits"
        );

        drop(db);
        remove(&path);
    }

    /// A member who left a room and missed two rotations pastes a fresh
    /// invite. Nothing it holds can check the key yet, so the key waits in
    /// memory, not on disk; the snapshot alone does not check it; the settings
    /// record naming its epoch does, and it is taken. A crafted key pasted
    /// beside it never is, and lapses.
    #[test]
    fn an_invite_this_device_could_not_check_is_taken_once_the_owners_records_catch_up() {
        let (path, db) = temp_db("catch-up");
        let pending = Mutex::new(PendingInviteKeys::default());
        let ident = member_room(&db, &secret(0));
        let id_hex = hex::encode(ident.channel_id);
        db.insert_channel_key_epoch(&id_hex, 1, &secret(1)).unwrap();
        let row = || db.get_channel(&id_hex).unwrap().unwrap();
        let epochs = || db.load_channel_key_epochs(&id_hex).unwrap();

        for offered in [secret(3), [0x99; 32]] {
            assert_eq!(
                take_offered_key_in(&db, &pending, &row(), ident.channel_id, 3, &offered, NOW).unwrap().key,
                OfferedKey::Held
            );
        }
        assert_eq!(epochs(), vec![(1, secret(1))], "nothing unchecked on disk");

        announce(&db, &ident, 3, 10);
        assert!(!settle_channel_keys_in(&db, &pending, ident.channel_id, false, NOW + 60));
        assert_eq!(row().key_epoch, 1, "a snapshot carries no commitment");

        assert!(ingest_channel_settings_records(&db, ident.channel_id, &[settings_blob(&ident, &[3, 2, 1], 1_000)]));
        assert!(settle_channel_keys_in(&db, &pending, ident.channel_id, true, NOW + 120));
        assert_eq!(row().key_epoch, 3);
        assert_eq!(epochs()[0], (3, secret(3)));
        assert!(epochs().iter().all(|(_, held)| *held != [0x99; 32]));

        let left = pending.lock().unwrap().for_room(&ident.channel_id, NOW + 120);
        assert_eq!(left.len(), 1, "the crafted key is still waiting, unchecked");
        assert!(!settle_channel_keys_in(&db, &pending, ident.channel_id, false, NOW + 180));
        assert!(pending
            .lock()
            .unwrap()
            .for_room(&ident.channel_id, NOW + PENDING_INVITE_KEY_SECS + 1)
            .is_empty());

        drop(db);
        remove(&path);
    }

    /// Waiting keys lapse, the same key offered twice is held once, and no
    /// more than the cap are held, the oldest giving way.
    #[test]
    fn pending_invite_keys_lapse_and_are_bounded() {
        let mut keys = PendingInviteKeys::default();
        let room = [0x31u8; 16];
        keys.hold(room, 2, &[2; 32], NOW);
        keys.hold(room, 2, &[2; 32], NOW + 1);
        assert_eq!(keys.for_room(&room, NOW + 1).len(), 1);
        assert!(keys.holds_room(&room, NOW + PENDING_INVITE_KEY_SECS));
        assert!(!keys.holds_room(&room, NOW + 1 + PENDING_INVITE_KEY_SECS));

        for i in 0..=PENDING_INVITE_KEYS_MAX {
            keys.hold([i as u8; 16], 1, &[i as u8; 32], NOW + i as i64);
        }
        assert!(!keys.holds_room(&[0u8; 16], NOW + 100), "the oldest gave way");
        let held: usize = (0..=PENDING_INVITE_KEYS_MAX)
            .map(|i| keys.for_room(&[i as u8; 16], NOW + 100).len())
            .sum();
        assert_eq!(held, PENDING_INVITE_KEYS_MAX);
    }

    /// A first join's crafted invite stored a wrong key at the room's epoch.
    /// The owner's commitment shows it is wrong, so it is dropped and the
    /// genuine key, from an invite that checks or the owner's sealed record,
    /// takes its place; nothing unchecked does. A wrong key at an epoch the
    /// owner never announced goes the same way, and a key the commitments
    /// vouch for stays.
    #[test]
    fn a_held_key_the_owners_commitments_contradict_gives_way_to_the_genuine_one() {
        let (path, db) = temp_db("contradicted");
        let pending = Mutex::new(PendingInviteKeys::default());
        let crafted = [0x66u8; 32];

        let ident = member_room(&db, &crafted);
        let id_hex = hex::encode(ident.channel_id);
        db.insert_channel_key_epoch(&id_hex, 3, &crafted).unwrap();
        announce(&db, &ident, 3, 10);
        let epochs = || db.load_channel_key_epochs(&id_hex).unwrap();
        let row = db.get_channel(&id_hex).unwrap().unwrap();
        assert_eq!(
            take_offered_key_in(&db, &pending, &row, ident.channel_id, 3, &secret(3), NOW).unwrap().key,
            OfferedKey::Held,
            "the slot is taken, so the genuine key waits"
        );
        assert_eq!(epochs(), vec![(3, crafted)]);
        assert!(ingest_channel_settings_records(&db, ident.channel_id, &[settings_blob(&ident, &[3, 2], 1_000)]));
        assert!(settle_channel_keys_in(&db, &pending, ident.channel_id, true, NOW + 60));
        assert_eq!(epochs(), vec![(3, secret(3))], "the crafted key gave way to the genuine one");

        let other = member_room(&db, &crafted);
        let other_hex = hex::encode(other.channel_id);
        db.insert_channel_key_epoch(&other_hex, 3, &crafted).unwrap();
        announce(&db, &other, 3, 10);
        assert!(ingest_channel_settings_records(&db, other.channel_id, &[settings_blob(&other, &[3, 2], 1_000)]));
        assert!(settle_channel_keys_in(&db, &pending, other.channel_id, true, NOW));
        let row = db.get_channel(&other_hex).unwrap().unwrap();
        assert!(db.load_channel_key_epochs(&other_hex).unwrap().is_empty());
        assert!(row.key_epoch_wanted > row.key_epoch, "behind again, so the key-epoch loop looks");
        assert_eq!(
            take_offered_key_in(&db, &pending, &row, other.channel_id, 3, &[0x77; 32], NOW).unwrap().key,
            OfferedKey::Held,
            "another unchecked key does not take the freed slot"
        );
        assert!(db.load_channel_key_epochs(&other_hex).unwrap().is_empty());
        assert!(!settle_channel_keys_in(&db, &pending, other.channel_id, true, NOW + 60), "nor ever will");
        db.insert_channel_key_epoch(&other_hex, 3, &secret(3))
            .expect("the owner's sealed record can be stored");

        let far = member_room(&db, &secret(0));
        let far_hex = hex::encode(far.channel_id);
        db.insert_channel_key_epoch(&far_hex, 2, &secret(2)).unwrap();
        db.insert_channel_key_epoch(&far_hex, 1_000, &crafted).unwrap();
        announce(&db, &far, 3, 10);
        assert!(ingest_channel_settings_records(&db, far.channel_id, &[settings_blob(&far, &[3, 2], 1_000)]));
        assert!(settle_channel_keys_in(&db, &pending, far.channel_id, true, NOW));
        assert_eq!(db.load_channel_key_epochs(&far_hex).unwrap(), vec![(2, secret(2))]);
        assert_eq!(db.get_channel(&far_hex).unwrap().unwrap().key_epoch, 2);
        assert_eq!(
            pending.lock().unwrap().for_room(&far.channel_id, NOW).len(),
            1,
            "kept in memory, in case a later record names it"
        );

        drop(db);
        remove(&path);
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
            language: String::new(),
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

/// Start storing each form of one of our records, with a verdict for each
/// publish that started. The caller drives the publishes.
fn start_own_channel_publishes(
    state: &mut NetworkState,
    records: Vec<ember::dht::publish::SignedRecord>,
) -> (Vec<u32>, Vec<oneshot::Receiver<EmberPublishResult>>) {
    let mut publish_ids = Vec::with_capacity(records.len());
    let mut verdicts = Vec::with_capacity(records.len());
    for record in records {
        if let Some(publish_id) = start_own_channel_publish(state, record) {
            let (tx, rx) = oneshot::channel();
            state.ember_dht_pending_publishes.insert(publish_id, tx);
            publish_ids.push(publish_id);
            verdicts.push(rx);
        }
    }
    (publish_ids, verdicts)
}

/// Whether any form of a record stored somewhere. During the transition a v2
/// form lands only on 1.7.5 storers and a v1 form on every storer, and a
/// reader takes either, so one landing is enough. A dropped sender means the
/// publish went away without a verdict, which is not evidence it landed.
async fn any_publish_stored(verdicts: Vec<oneshot::Receiver<EmberPublishResult>>) -> bool {
    for rx in verdicts {
        if rx.await.is_ok_and(|result| result.stored_on > 0) {
            return true;
        }
    }
    false
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
    let language = settings.channel_language_code();
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
        // Nor the newest epoch we hold, when the room has moved past it: a
        // member behind the room's key, or a recovered room of ours still
        // fetching its key back, would announce itself under a key only the
        // evicted can read. Looked at again after a retry interval rather than
        // left due, where it would take one of this tick's slots every tick.
        if private && private_room_key_behind(db, &ch) {
            let _ = db.touch_channel_presence(
                &channel_id_hex,
                now - ember::channel::PRESENCE_REPUBLISH_SECS + ember::channel::PRESENCE_RETRY_SECS,
            );
            continue;
        }
        // The current epoch, not the `join_secret` column: a private room's
        // presence extra is sealed with the content key, and publishing it under
        // a retired epoch would leave an evicted member able to enumerate the
        // room's membership while the members who rotated could not read it.
        let Some(join_secret) = current_channel_join_secret(db, &ch) else {
            continue;
        };
        let records = ember::dht::publish::SignedRecord::channel_presence_forms(
            &nickname,
            language,
            channel_id,
            channel_pubkey,
            &join_secret,
            private,
            false,
            &identity.noise_public_key,
            &signing,
            now,
        );
        let (publish_ids, verdicts) = start_own_channel_publishes(state, records);
        if !publish_ids.is_empty() {
            // Stamped up front so the next scan does not start a second publish
            // for this room while the first is still in flight. Our own
            // last_seen has to move with the announce too: gossip neighbors
            // and the empty-room poll both read `channel_members.last_seen`,
            // and that row was otherwise only written on join — so twenty
            // minutes later we had dropped out of our own roster's "fresh" set
            // while still sitting in the room.
            let _ = db.touch_channel_presence(&channel_id_hex, now);
            let _ = db.upsert_channel_member_with_language(
                &channel_id_hex,
                &hex::encode(identity.ed25519_public_key),
                &nickname,
                Some(language.unwrap_or("")),
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
            let retry_db = db.clone();
            let retry_id = channel_id_hex.clone();
            let retry_at = now - ember::channel::PRESENCE_REPUBLISH_SECS
                + ember::channel::PRESENCE_RETRY_SECS;
            tokio::spawn(async move {
                if any_publish_stored(verdicts).await {
                    return;
                }
                let _ = retry_db.retry_channel_presence(&retry_id, now, retry_at);
            });
            for publish_id in publish_ids {
                drive_ember_publish(socket, state, publish_id).await;
            }
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
///
/// A new Channel language is published the same way, and for the same reason.
#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_presence_under_new_username(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    settings: &AppSettings,
    identity: &crate::storage::identity::NodeIdentity,
    old_username: &str,
    old_language: Option<&'static str>,
) {
    let new = settings.channel_username.trim();
    let language = settings.channel_language_code();
    let renamed = new != old_username.trim();
    if new.is_empty() || (!renamed && language == old_language) {
        return;
    }
    let pk = hex::encode(identity.ed25519_public_key);
    if renamed {
        let _ = db.rename_self_channel_member(&pk, new);
    }
    if language != old_language {
        // The settings save relabelled these rows already, so this usually
        // finds nothing. It catches a publish that ran on the old settings
        // in between and wrote the old language back.
        if let Ok(rooms) = db.set_self_channel_member_language(&pk, language.unwrap_or("")) {
            for room in rooms {
                let _ = app_handle.emit(
                    "ember:channel-members",
                    serde_json::json!({ "channel_id": room }),
                );
            }
        }
    }
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
        // Behind the room's key, our presence was never readable under the key
        // members look at now, so there is nothing for a notice to retract —
        // and one sealed under the key we do hold would only reach the evicted.
        if ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE && private_room_key_behind(db, &ch) {
            let _ = db.clear_channel_departure(&channel_id_hex);
            continue;
        }
        // The epoch the room is on now, not the one we left under: the presence
        // key is derived from it, and members are only looking at the current
        // one.
        let Some(join_secret) = current_channel_join_secret(db, &ch) else {
            let _ = db.clear_channel_departure(&channel_id_hex);
            continue;
        };
        let records = ember::dht::publish::SignedRecord::channel_presence_forms(
            &nickname,
            None,
            cid,
            cpk,
            &join_secret,
            ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE,
            true,
            &identity.noise_public_key,
            &signing,
            now,
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
        let (publish_ids, verdicts) = start_own_channel_publishes(state, records);
        if publish_ids.is_empty() {
            continue;
        }
        // Cleared only once a node says it stored the record. Clearing on the
        // attempt is the bug this whole function exists to fix, one layer up.
        let retry_db = db.clone();
        let retry_id = channel_id_hex.clone();
        tokio::spawn(async move {
            if any_publish_stored(verdicts).await {
                let _ = retry_db.clear_channel_departure(&retry_id);
            }
        });
        for publish_id in publish_ids {
            drive_ember_publish(socket, state, publish_id).await;
        }
    }
    publish_owed_channel_departures(socket, state, db, &nickname, identity, &signing, now).await;
}

/// Leave notices owed for rooms whose row is already gone: forgotten after a
/// leave that had not landed, or destroyed by their owner. The room's key was
/// captured when the notice became owed (see
/// `Database::owed_channel_departures`); otherwise retried exactly like the
/// in-room notices above.
async fn publish_owed_channel_departures(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    nickname: &str,
    identity: &crate::storage::identity::NodeIdentity,
    signing: &ed25519_dalek::SigningKey,
    now: i64,
) {
    let Ok(owed) = db.owed_channel_departures(now) else {
        return;
    };
    for departure in owed.into_iter().take(2) {
        let Ok(cid) = hex::decode(&departure.channel_id)
            .map_err(|_| ())
            .and_then(|b| <[u8; 16]>::try_from(b).map_err(|_| ()))
        else {
            let _ = db.clear_owed_channel_departure(&departure.channel_id);
            continue;
        };
        let retry_at = now + ember::channel::PRESENCE_RETRY_SECS;
        if !db
            .claim_owed_channel_departure(&departure.channel_id, retry_at)
            .unwrap_or(false)
        {
            continue;
        }
        let records = ember::dht::publish::SignedRecord::channel_presence_forms(
            nickname,
            None,
            cid,
            departure.channel_pubkey,
            &departure.join_secret,
            departure.private,
            true,
            &identity.noise_public_key,
            signing,
            now,
        );
        let (publish_ids, verdicts) = start_own_channel_publishes(state, records);
        if publish_ids.is_empty() {
            continue;
        }
        let retry_db = db.clone();
        let retry_id = departure.channel_id.clone();
        tokio::spawn(async move {
            if any_publish_stored(verdicts).await {
                let _ = retry_db.clear_owed_channel_departure(&retry_id);
            }
        });
        for publish_id in publish_ids {
            drive_ember_publish(socket, state, publish_id).await;
        }
    }
}

/// A private room whose current key this device does not hold yet: the owner
/// has announced a newer epoch than the newest held, or this is a recovered
/// room of ours still fetching its key back. A failed read counts as behind.
fn private_room_key_behind(db: &Database, ch: &crate::storage::database::StoredChannel) -> bool {
    if ch.visibility != ember::channel::CHANNEL_KIND_PRIVATE {
        return false;
    }
    ch.key_epoch_wanted > ch.key_epoch
        || db
            .channel_owner_key_pending(&ch.channel_id)
            .map_or(true, |pending| pending.is_some())
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
    if let Some(snapshot) = channel_roster_held(state, db, channel_id) {
        return snapshot;
    }
    let snapshot = Arc::new(read_channel_roster(db, channel_id));
    hold_channel_roster(state, channel_id, &snapshot);
    snapshot
}

/// The room's held roster snapshot while it is still exact. Reads only the
/// in-memory generation, never the table.
pub(super) fn channel_roster_held(
    state: &NetworkState,
    db: &Database,
    channel_id: [u8; 16],
) -> Option<Arc<ChannelRosterSnapshot>> {
    let generation = db.channel_roster_generation(&hex::encode(channel_id));
    state
        .channel_view_cache
        .get(&channel_id)
        .and_then(|view| view.roster.as_ref())
        .filter(|snapshot| snapshot.valid_at(generation, std::time::Instant::now()))
        .cloned()
}

/// Read the room's roster from the table. Blocking: off the loop where the
/// caller can be.
pub(super) fn read_channel_roster(db: &Database, channel_id: [u8; 16]) -> ChannelRosterSnapshot {
    let now = std::time::Instant::now();
    let channel_id_hex = hex::encode(channel_id);
    let generation = db.channel_roster_generation(&channel_id_hex);
    match db.list_channel_members(&channel_id_hex) {
        Ok(rows) => ChannelRosterSnapshot::from_rows(rows, generation, now),
        Err(e) => {
            debug!("Channel roster read failed for {channel_id_hex}: {e}");
            ChannelRosterSnapshot::unreadable(now)
        }
    }
}

/// Keep a roster read for the room's next callers. An unreadable one is not
/// kept, so the next caller reads again: kept as an empty roster, a transient
/// error was a room where nobody was banned for the next 30 s.
pub(super) fn hold_channel_roster(state: &mut NetworkState, channel_id: [u8; 16], snapshot: &Arc<ChannelRosterSnapshot>) {
    if snapshot.unreadable {
        return;
    }
    if let Some(view) = state.channel_view_cache.get_mut(&channel_id) {
        view.roster = Some(snapshot.clone());
    }
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
    channel_join_secrets(db, ch)
        .iter()
        .map(ember::channel::content_key)
        .collect()
}

/// The join secrets behind [`channel_content_keys`], in the same order.
pub(super) fn channel_join_secrets(
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
        return vec![ember::channel::public_join_secret(&pk)];
    }
    let mut secrets: Vec<[u8; 32]> = db
        .load_channel_key_epochs(&ch.channel_id)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, secret)| secret)
        .collect();
    // Epoch 0 is the secret the invite was minted with, still in `join_secret`
    // for any room that has never rotated.
    if let Ok(Some(secret)) = db.load_channel_join_secret(&ch.channel_id) {
        if !secrets.contains(&secret) {
            secrets.push(secret);
        }
    }
    secrets
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
            && !ember::channel::beacon_admits_newcomer(&beacon, &channel_id, admission_key.as_ref())
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
        let last = state
            .channel_moderation_fetch_at
            .get(&channel_id)
            .copied()
            .unwrap_or(0);
        if !ember::channel::schedule_due(last, now, ember::channel::MODERATION_FETCH_SECS) {
            continue;
        }
        match start_channel_moderation_fetch(socket, state, ch, channel_id, now).await {
            None => break,
            Some(false) => continue,
            Some(true) => started += 1,
        }
    }
}

/// FIND_VALUE one room's owner-signed snapshot, counted as one of its
/// moderation passes. `Some(false)` when one is already in flight for the
/// room, `None` when no search could start.
async fn start_channel_moderation_fetch(
    socket: &UdpSocket,
    state: &mut NetworkState,
    ch: &crate::storage::database::StoredChannel,
    channel_id: [u8; 16],
    now: i64,
) -> Option<bool> {
    if state
        .ember_channel_moderation_searches
        .values()
        .any(|id| *id == channel_id)
    {
        return Some(false);
    }
    let key = ember::channel::moderation_key(&channel_id);
    let search_id = state.ember_search.start_background_find_value(
        ember::dht::EmberNodeId(key),
        Vec::new(),
        state.ember_dht.routing(),
    )?;
    seed_ember_local_records(state, search_id, &key, &[]);
    state
        .ember_channel_moderation_searches
        .insert(search_id, channel_id);
    drive_ember_search(socket, state, search_id).await;
    state.channel_moderation_fetch_at.insert(channel_id, now);
    let pass = state.channel_moderation_passes.entry(channel_id).or_insert(0);
    if settings_fetch_rides_pass(*pass, ch) {
        state.channel_settings_fetch_owed.insert(channel_id);
    }
    *pass += 1;
    Some(true)
}

/// Settings lookups ride the moderation pass: one on every this many, the
/// first included, which with [`ember::channel::MODERATION_FETCH_SECS`] is
/// every fifteen minutes. A pass can also ask for one at once
/// ([`settings_owed_after_pass`]), which is the case a member behind the
/// room's key needs: the commitments to the epoch it was just told of.
const CHANNEL_SETTINGS_FETCH_EVERY_PASSES: u64 = 3;
pub(super) const CHANNEL_SETTINGS_FETCH_PER_TICK: usize = 2;

/// Whether moderation pass number `pass` (from 0) of `ch` this session also
/// looks its settings record up.
fn settings_fetch_rides_pass(pass: u64, ch: &crate::storage::database::StoredChannel) -> bool {
    pass.is_multiple_of(CHANNEL_SETTINGS_FETCH_EVERY_PASSES) && channel_settings_fetched_for(ch)
}

/// Whether a room's settings record is looked up at once after one of its
/// moderation passes came back, `row` as it stands after the pass and `held`
/// the settings record held for it: the snapshot named a newer key epoch than
/// any before (`wanted_before`), or this device is behind the room's key and
/// holds no commitment to the epoch the owner announced. The second covers a
/// lookup that ran before the owner's record moved, and a pass that found the
/// snapshot already held.
fn settings_owed_after_pass(
    wanted_before: Option<i64>,
    row: &crate::storage::database::StoredChannel,
    held: Option<&crate::storage::database::HeldChannelSettings>,
) -> bool {
    if !channel_settings_fetched_for(row) {
        return false;
    }
    wanted_before.is_some_and(|before| row.key_epoch_wanted > before)
        || (row.key_epoch_wanted > row.key_epoch
            && held.is_none_or(|held| {
                !held
                    .key_commitments
                    .iter()
                    .any(|(epoch, _)| *epoch == row.key_epoch_wanted)
            }))
}

/// The longest a room stays without one of the lookups
/// [`settings_owed_after_pass`] asks for while it is owed them.
const SETTINGS_LOOKUP_BACKOFF_MAX_SECS: i64 = 6 * 60 * 60;

/// How long each room behind its key waits before the next lookup
/// [`settings_owed_after_pass`] asks for, and since which epochs.
#[derive(Default)]
struct SettingsLookupBackoff(HashMap<[u8; 16], SettingsLookupWait>);

struct SettingsLookupWait {
    /// `(key_epoch_wanted, key_epoch)` when the room first fell owed.
    epochs: (i64, i64),
    wait: i64,
    next_at: i64,
}

impl SettingsLookupBackoff {
    fn forget(&mut self, channel_id: &[u8; 16]) {
        self.0.remove(channel_id);
    }

    /// Keep only the rooms `kept` holds to: one left or deleted is never
    /// looked up again, and would otherwise stay here for the session.
    fn retain_rooms(&mut self, mut kept: impl FnMut(&[u8; 16]) -> bool) {
        self.0.retain(|channel_id, _| kept(channel_id));
    }
}

fn settings_lookup_backoff() -> &'static std::sync::Mutex<SettingsLookupBackoff> {
    static BACKOFF: std::sync::OnceLock<std::sync::Mutex<SettingsLookupBackoff>> = std::sync::OnceLock::new();
    BACKOFF.get_or_init(Default::default)
}

/// Whether a lookup [`settings_owed_after_pass`] asks for goes out now, for
/// a room whose `(key_epoch_wanted, key_epoch)` are `epochs`.
///
/// The first does, and the next one moderation pass later; after that each
/// waits twice as long as the one before, up to
/// [`SETTINGS_LOOKUP_BACKOFF_MAX_SECS`]. An owner on a build before 1.7.5
/// never publishes kind 8, so a member behind its key may stay owed a lookup
/// indefinitely, and lookups that never answer must not go out every pass. A
/// move of either epoch starts over, and so does a settings record landing
/// (the caller forgets the room). The lookup that rides every third pass is
/// not held back by this.
fn settings_lookup_backoff_allows(
    backoff: &mut SettingsLookupBackoff,
    channel_id: [u8; 16],
    epochs: (i64, i64),
    now: i64,
) -> bool {
    // Passes come about MODERATION_FETCH_SECS apart, give or take how long
    // each lookup took to answer.
    let slack = ember::channel::MODERATION_FETCH_SECS / 2;
    match backoff.0.get_mut(&channel_id) {
        Some(wait) if wait.epochs == epochs => {
            if now + slack < wait.next_at {
                return false;
            }
            wait.wait = (wait.wait * 2).min(SETTINGS_LOOKUP_BACKOFF_MAX_SECS);
            wait.next_at = now + wait.wait;
            true
        }
        _ => {
            backoff.0.insert(
                channel_id,
                SettingsLookupWait {
                    epochs,
                    wait: ember::channel::MODERATION_FETCH_SECS,
                    next_at: now + ember::channel::MODERATION_FETCH_SECS,
                },
            );
            true
        }
    }
}

/// Drop the bookkeeping of a settings lookup given up on before it finished,
/// leaving the room owed one: the walk answered nothing either way.
pub(super) fn rearm_abandoned_settings_lookup(
    searches: &mut HashMap<u32, [u8; 16]>,
    owed: &mut HashSet<[u8; 16]>,
    search_id: u32,
) {
    if let Some(channel_id) = searches.remove(&search_id) {
        owed.insert(channel_id);
    }
}

/// Look a held private room's snapshot and settings record up now rather
/// than on their schedules: sent when an invite brought a key nothing held
/// could check yet ([`OfferedKey::Held`]), so this device's view of the room
/// is stale and the key waits on what these say.
pub(super) async fn refresh_channel_owner_records_now(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
    channel_id: [u8; 16],
) {
    if !settings.ember_native_enabled || db.chat_locked() {
        return;
    }
    let read = {
        let db = db.clone();
        tokio::task::spawn_blocking(move || db.get_channel_lite(&hex::encode(channel_id))).await
    };
    let Ok(Ok(Some(ch))) = read else {
        return;
    };
    if !channel_settings_fetched_for(&ch) {
        return;
    }
    // The room has just been entered, which the cached roster may not show
    // yet, and the settings loop drops a mark for a room it sees as left.
    state.channel_roster_cache = None;
    let now = chrono::Utc::now().timestamp();
    let _ = start_channel_moderation_fetch(socket, state, &ch, channel_id, now).await;
    state.channel_settings_fetch_owed.insert(channel_id);
    let _ = start_channel_settings_fetch(socket, state, channel_id).await;
}

/// Whether this device looks up a room's settings record at all.
///
/// The fields this build reads, the key commitments and the admission rule,
/// mean something only in a private room, and an owner applies its own, so for
/// a public room or one we own the lookup would cost a walk and could change
/// nothing here. A build that gives public rooms a setting widens this.
fn channel_settings_fetched_for(ch: &crate::storage::database::StoredChannel) -> bool {
    ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE && !ch.is_owner && !ch.deleted
}

/// FIND_VALUE the owner-signed settings record of each room owed a lookup.
pub(super) async fn maybe_refresh_channel_settings(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    settings: &AppSettings,
) {
    if !settings.ember_native_enabled
        || db.chat_locked()
        || state.channel_settings_fetch_owed.is_empty()
    {
        return;
    }
    let Some(channels) = channels_lite_cached(state, db) else {
        return;
    };
    let mut started = 0usize;
    for ch in channels.iter() {
        if started >= CHANNEL_SETTINGS_FETCH_PER_TICK {
            break;
        }
        let Some(channel_id) = hex::decode(&ch.channel_id)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
        else {
            continue;
        };
        if !state.channel_settings_fetch_owed.contains(&channel_id) {
            continue;
        }
        if !ch.in_room_now() || !channel_settings_fetched_for(ch) {
            state.channel_settings_fetch_owed.remove(&channel_id);
            continue;
        }
        match start_channel_settings_fetch(socket, state, channel_id).await {
            None => break,
            Some(false) => continue,
            Some(true) => started += 1,
        }
    }
    // Rooms that are no longer on the roster at all.
    state.channel_settings_fetch_owed.retain(|id| {
        let id_hex = hex::encode(id);
        channels.iter().any(|ch| ch.channel_id == id_hex)
    });
}

/// FIND_VALUE one room's settings record, settling the lookup it owed.
/// `Some(false)` when one is already in flight, which leaves the owed mark
/// for the next pass; `None` when no search could start.
async fn start_channel_settings_fetch(
    socket: &UdpSocket,
    state: &mut NetworkState,
    channel_id: [u8; 16],
) -> Option<bool> {
    if state
        .ember_channel_settings_searches
        .values()
        .any(|id| *id == channel_id)
    {
        return Some(false);
    }
    let key = ember::channel::settings_key(&channel_id);
    let search_id = state.ember_search.start_background_find_value(
        ember::dht::EmberNodeId(key),
        Vec::new(),
        state.ember_dht.routing(),
    )?;
    seed_ember_local_records(state, search_id, &key, &[]);
    state
        .ember_channel_settings_searches
        .insert(search_id, channel_id);
    state.channel_settings_fetch_owed.remove(&channel_id);
    drive_ember_search(socket, state, search_id).await;
    Some(true)
}

/// Hold the newest owner-signed settings record among `records` for a room on
/// this device, if it supersedes the copy held. Returns whether it did.
///
/// Found records only ever replace one held: a lookup that finds none, or
/// finds only older ones, leaves every setting as it was.
pub(crate) fn ingest_channel_settings_records(
    db: &Database,
    channel_id: [u8; 16],
    records: &[Vec<u8>],
) -> bool {
    if db.chat_locked() {
        return false;
    }
    let channel_id_hex = hex::encode(channel_id);
    let Ok(Some(ch)) = db.get_channel_lite(&channel_id_hex) else {
        return false;
    };
    let Ok(stored_pk) = hex::decode(&ch.pubkey) else {
        return false;
    };
    let mut best: Option<ember::dht::publish::ChannelSettings> = None;
    for blob in records {
        // Parsing holds the publisher to the key the record names as the room's,
        // and the room's id to that key; this holds it to the key we joined.
        let Some(parsed) =
            ember::dht::publish::SignedRecord::parse_channel_settings(blob, &channel_id)
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
    let Some(settings) = best else {
        return false;
    };
    db.ingest_channel_settings(
        &channel_id_hex,
        &crate::storage::database::HeldChannelSettings {
            signed_at: settings.timestamp,
            signature: settings.signature,
            key_commitments: settings.key_commitments,
            admission: settings.admission,
        },
    )
    .unwrap_or(false)
}

/// The admission rule this device holds a private room's chat lines to.
///
/// The owner applies the one it states ([`ember::channel::RosterAdmission::OWNED_PRIVATE_ROOM`])
/// from launch rather than from its first publish. A member applies the
/// newest settings record it holds, and with none the rule before 1.7.5. A
/// failed read is taken as the strict rule.
pub(super) fn private_room_admission(
    db: &Database,
    channel_id_hex: &str,
    own_room: bool,
) -> ember::channel::RosterAdmission {
    if own_room {
        return ember::channel::RosterAdmission::OWNED_PRIVATE_ROOM;
    }
    match db.channel_settings(channel_id_hex) {
        Ok(held) => held.map_or(ember::channel::RosterAdmission::Open, |held| {
            ember::channel::RosterAdmission::from_setting(held.admission)
        }),
        Err(_) => ember::channel::RosterAdmission::KeyProven,
    }
}

/// How long a key offered for a held room is kept for the owner's records to
/// catch up with it, when nothing this device holds can check it yet.
const PENDING_INVITE_KEY_SECS: i64 = 30 * 60;
/// How many such keys are kept at once, across every room.
const PENDING_INVITE_KEYS_MAX: usize = 16;

struct PendingInviteKey {
    channel_id: [u8; 16],
    epoch: i64,
    secret: zeroize::Zeroizing<[u8; 32]>,
    until: i64,
}

/// Keys offered for private rooms this device holds that no commitment it
/// holds checks yet: an invite pasted while its view of the room was behind,
/// or a key the owner's commitments showed was not the room's. Each is taken
/// only once a commitment checks it ([`committed_key_epoch`]), and lapses
/// after [`PENDING_INVITE_KEY_SECS`].
///
/// In memory only. Nothing here has been checked, and the store keeps the
/// first key an epoch is given.
#[derive(Default)]
pub(crate) struct PendingInviteKeys(Vec<PendingInviteKey>);

impl PendingInviteKeys {
    fn hold(&mut self, channel_id: [u8; 16], epoch: i64, secret: &[u8; 32], now: i64) {
        self.prune(now);
        self.0.retain(|held| {
            !(held.channel_id == channel_id && held.epoch == epoch && *held.secret == *secret)
        });
        self.0.push(PendingInviteKey {
            channel_id,
            epoch,
            secret: zeroize::Zeroizing::new(*secret),
            until: now.saturating_add(PENDING_INVITE_KEY_SECS),
        });
        let excess = self.0.len().saturating_sub(PENDING_INVITE_KEYS_MAX);
        self.0.drain(..excess);
    }

    fn prune(&mut self, now: i64) {
        self.0.retain(|held| now < held.until);
    }

    fn holds_room(&mut self, channel_id: &[u8; 16], now: i64) -> bool {
        self.prune(now);
        self.0.iter().any(|held| held.channel_id == *channel_id)
    }

    /// The keys held for a room, newest epoch first.
    fn for_room(&mut self, channel_id: &[u8; 16], now: i64) -> Vec<(i64, zeroize::Zeroizing<[u8; 32]>)> {
        self.prune(now);
        let mut keys: Vec<_> = self
            .0
            .iter()
            .filter(|held| held.channel_id == *channel_id)
            .map(|held| (held.epoch, held.secret.clone()))
            .collect();
        keys.sort_by_key(|(epoch, _)| std::cmp::Reverse(*epoch));
        keys
    }

    fn forget(&mut self, channel_id: &[u8; 16], epoch: i64, secret: &[u8; 32]) {
        self.0.retain(|held| {
            !(held.channel_id == *channel_id && held.epoch == epoch && *held.secret == *secret)
        });
    }

    fn forget_room(&mut self, channel_id: &[u8; 16]) {
        self.0.retain(|held| held.channel_id != *channel_id);
    }
}

fn pending_invite_keys() -> &'static std::sync::Mutex<PendingInviteKeys> {
    static KEYS: std::sync::OnceLock<std::sync::Mutex<PendingInviteKeys>> = std::sync::OnceLock::new();
    KEYS.get_or_init(Default::default)
}

fn lock_pending(
    pending: &std::sync::Mutex<PendingInviteKeys>,
) -> std::sync::MutexGuard<'_, PendingInviteKeys> {
    pending.lock().unwrap_or_else(|e| e.into_inner())
}

/// The epoch a key offered for `row`, a room this device already holds, may
/// be taken as; `None` when it may not.
///
/// An invite is unauthenticated and the store keeps the first key it is given
/// for an epoch, so one taken unchecked would have this device seal under a
/// key the invite's author reads, and refuse the genuine one when it came: why
/// 1.7.3 stopped taking them. What makes it safe now is the owner's commitment
/// to each kept epoch's key, carried in a record only the room key signs. So
/// only a private room this device is behind in, by what the owner announced
/// or by the epoch offered being past the newest it holds, only a key that
/// says which epoch it is (epoch 0 does not), and only where the newest
/// settings record held names that epoch with a matching commitment.
pub(crate) fn committed_key_epoch(
    row: &crate::storage::database::StoredChannel,
    channel_id: &[u8; 16],
    epoch: i64,
    secret: &[u8; 32],
    held: Option<&crate::storage::database::HeldChannelSettings>,
) -> Option<i64> {
    if row.visibility != ember::channel::CHANNEL_KIND_PRIVATE
        || epoch < 1
        || (row.key_epoch_wanted <= row.key_epoch && epoch <= row.key_epoch)
    {
        return None;
    }
    let (_, commitment) = held?
        .key_commitments
        .iter()
        .find(|(committed, _)| *committed == epoch)?;
    let offered = ember::channel::key_commitment(channel_id, epoch, &ember::channel::content_key(secret));
    (offered == *commitment).then_some(epoch)
}

/// The keys among `epochs` (as `load_channel_key_epochs` reads them) the
/// owner's commitments in `held` show are not the room's, for a private room
/// this device holds and does not own:
///
/// - an epoch `held` names, under a different commitment;
/// - once a snapshot has been taken for the room (`moderation_updated_at`),
///   an epoch past both the newest `held` names and the newest the owner's
///   snapshot announced (`key_epoch_wanted`). Only a first join's unchecked
///   invite stores one: the key-epoch loop fetches no epoch past
///   `key_epoch_wanted`, and an invite to a held room is taken only against a
///   commitment. Before the first snapshot `key_epoch_wanted` is still 0, and
///   a settings record looked up first can predate the rotation the invite's
///   key came from, so a genuine key would read as past both.
///
/// With no commitments held there is nothing to judge by, so nothing.
fn epochs_contradicting_commitments(
    row: &crate::storage::database::StoredChannel,
    channel_id: &[u8; 16],
    epochs: &[(i64, [u8; 32])],
    held: &crate::storage::database::HeldChannelSettings,
) -> Vec<(i64, [u8; 32])> {
    if row.visibility != ember::channel::CHANNEL_KIND_PRIVATE || row.is_owner {
        return Vec::new();
    }
    let Some(newest_committed) = held.key_commitments.iter().map(|(epoch, _)| *epoch).max() else {
        return Vec::new();
    };
    let announced = row.moderation_updated_at > 0;
    epochs
        .iter()
        .filter(|(epoch, secret)| {
            if *epoch < 1 {
                return false;
            }
            match held.key_commitments.iter().find(|(committed, _)| committed == epoch) {
                Some((_, commitment)) => {
                    ember::channel::key_commitment(channel_id, *epoch, &ember::channel::content_key(secret))
                        != *commitment
                }
                None => announced && *epoch > newest_committed && *epoch > row.key_epoch_wanted,
            }
        })
        .copied()
        .collect()
}

/// Whether a moderation pass for a held room calls for the held keys to be
/// judged again ([`settle_channel_keys`] with `check_held`): it applied a
/// snapshot that raised `key_epoch_wanted`, or the room's first, either of
/// which can turn a key past everything announced into one the commitments
/// contradict. `before` and `after` are the room's row around the pass.
fn moderation_pass_rechecks_keys(
    applied: bool,
    before: Option<&crate::storage::database::StoredChannel>,
    after: &crate::storage::database::StoredChannel,
) -> bool {
    applied
        && before.is_some_and(|before| {
            after.key_epoch_wanted > before.key_epoch_wanted || before.moderation_updated_at == 0
        })
}

/// Bring a held private room's keys in line with what its owner has signed,
/// after one of the owner's records was looked up: with `check_held` (a
/// settings record has just been taken, or a snapshot that moves what the
/// commitments are judged against, [`moderation_pass_rechecks_keys`]), drop
/// each held key the commitments contradict
/// ([`epochs_contradicting_commitments`]), keeping it in memory in case a
/// later record vouches for it after all; then take any key waiting in memory
/// that a commitment now checks. Returns whether the room's keys changed.
/// Blocking.
pub(crate) fn settle_channel_keys(db: &Database, channel_id: [u8; 16], check_held: bool) -> bool {
    let now = chrono::Utc::now().timestamp();
    let pending = pending_invite_keys();
    if !check_held && !lock_pending(pending).holds_room(&channel_id, now) {
        return false;
    }
    settle_channel_keys_in(db, pending, channel_id, check_held, now)
}

fn settle_channel_keys_in(
    db: &Database,
    pending: &std::sync::Mutex<PendingInviteKeys>,
    channel_id: [u8; 16],
    check_held: bool,
    now: i64,
) -> bool {
    let channel_id_hex = hex::encode(channel_id);
    let Ok(Some(mut row)) = db.get_channel_lite(&channel_id_hex) else {
        return false;
    };
    if row.visibility != ember::channel::CHANNEL_KIND_PRIVATE || row.is_owner || row.deleted {
        lock_pending(pending).forget_room(&channel_id);
        return false;
    }
    let held = db.channel_settings(&channel_id_hex).ok().flatten();
    let mut changed = false;
    if let Some(settings) = held.as_ref().filter(|_| check_held) {
        let epochs = db.load_channel_key_epochs(&channel_id_hex).unwrap_or_default();
        let contradicted = epochs_contradicting_commitments(&row, &channel_id, &epochs, settings);
        match db.drop_channel_key_epochs(&channel_id_hex, &contradicted) {
            Ok(dropped) if dropped.is_empty() => {}
            Ok(dropped) => {
                info!(
                    "Ember channel {channel_id_hex}: dropped key epochs {dropped:?}, which the \
                     owner's commitments show are not the room's"
                );
                changed = true;
                let mut keys = lock_pending(pending);
                for (epoch, secret) in contradicted.iter().filter(|(epoch, _)| dropped.contains(epoch)) {
                    keys.hold(channel_id, *epoch, secret, now);
                }
            }
            Err(e) => debug!("Ember channel {channel_id_hex}: could not drop contradicted key epochs: {e}"),
        }
        if changed {
            match db.get_channel_lite(&channel_id_hex) {
                Ok(Some(fresh)) => row = fresh,
                _ => return changed,
            }
        }
    }
    let offered = lock_pending(pending).for_room(&channel_id, now);
    for (epoch, secret) in offered {
        if epoch < row.key_epoch {
            lock_pending(pending).forget(&channel_id, epoch, &secret);
            continue;
        }
        let Some(epoch) = committed_key_epoch(&row, &channel_id, epoch, &secret, held.as_ref()) else {
            continue;
        };
        match db.insert_channel_key_epoch(&channel_id_hex, epoch, &secret) {
            Ok(()) => {
                info!("Ember channel {channel_id_hex}: took an invite's key for epoch {epoch} against the owner's commitment");
                lock_pending(pending).forget(&channel_id, epoch, &secret);
                changed = true;
                match db.get_channel_lite(&channel_id_hex) {
                    Ok(Some(fresh)) => row = fresh,
                    _ => break,
                }
            }
            Err(e) => debug!("Ember channel {channel_id_hex}: committed key for epoch {epoch} not stored: {e}"),
        }
    }
    changed
}

/// What became of a key offered for a held room ([`take_offered_key`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OfferedKey {
    /// A commitment checked it, and it is stored.
    Taken,
    /// Nothing held can check it yet, so it waits in memory for the owner's
    /// records ([`PendingInviteKeys`]).
    Held,
    Refused,
}

/// What [`take_offered_key`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OfferedKeyOutcome {
    pub(crate) key: OfferedKey,
    /// The room's keys changed: the key was taken, or a held key the
    /// commitments contradict was dropped first. The caller tells the network
    /// loop, as an ingest that changes them does
    /// ([`ChannelIngestResults::rekeyed`]).
    pub(crate) rekeyed: bool,
}

/// Take a key an invite offers for `row`, a private room this device already
/// holds, if a commitment checks it; otherwise keep it in memory when it
/// names an epoch this device does not hold the same key for, at or past the
/// newest it holds, which is what a device whose view of the room is stale
/// sees. Held keys the commitments contradict are dropped first, so the
/// genuine key can take their place. Blocking.
pub(crate) fn take_offered_key(
    db: &Database,
    row: &crate::storage::database::StoredChannel,
    channel_id: [u8; 16],
    epoch: i64,
    secret: &[u8; 32],
) -> anyhow::Result<OfferedKeyOutcome> {
    take_offered_key_in(db, pending_invite_keys(), row, channel_id, epoch, secret, chrono::Utc::now().timestamp())
}

fn take_offered_key_in(
    db: &Database,
    pending: &std::sync::Mutex<PendingInviteKeys>,
    row: &crate::storage::database::StoredChannel,
    channel_id: [u8; 16],
    epoch: i64,
    secret: &[u8; 32],
    now: i64,
) -> anyhow::Result<OfferedKeyOutcome> {
    let refused = |rekeyed| OfferedKeyOutcome {
        key: OfferedKey::Refused,
        rekeyed,
    };
    if row.visibility != ember::channel::CHANNEL_KIND_PRIVATE || epoch < 1 {
        return Ok(refused(false));
    }
    let settled = settle_channel_keys_in(db, pending, channel_id, true, now);
    let Some(row) = db.get_channel_lite(&row.channel_id)? else {
        return Ok(refused(settled));
    };
    let held = db.channel_settings(&row.channel_id)?;
    if let Some(epoch) = committed_key_epoch(&row, &channel_id, epoch, secret, held.as_ref()) {
        db.insert_channel_key_epoch(&row.channel_id, epoch, secret)?;
        return Ok(OfferedKeyOutcome {
            key: OfferedKey::Taken,
            rekeyed: true,
        });
    }
    let holds_it = epoch == row.key_epoch
        && db
            .load_channel_key_epochs(&row.channel_id)?
            .iter()
            .any(|(held_epoch, held_secret)| *held_epoch == epoch && held_secret == secret);
    if row.is_owner || epoch < row.key_epoch || holds_it {
        return Ok(refused(settled));
    }
    lock_pending(pending).hold(channel_id, epoch, secret, now);
    Ok(OfferedKeyOutcome {
        key: OfferedKey::Held,
        rekeyed: settled,
    })
}

pub(crate) fn ingest_channel_moderation_records(
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

/// Owners re-STORE the records only they can sign, so their DHT TTL cannot age
/// them out while the owner is about: the moderation record, plus the
/// public-index listing for public rooms. Remaining life is derived from the
/// publisher's signed creation time, so replication between storers cannot
/// stand in for the owner re-signing (see `DhtStore::store`). The lifetimes
/// themselves are long (see `record_ttl`) for the owner's sake as much as the
/// members': a restored device rebuilds the rooms it owns from these.
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
        // Behind the schedule, so only a room that is due costs the reads.
        if owner_republish_held_back(db, &ch.channel_id) {
            continue;
        }
        // A commitment this device did not offer: a record it found stored, or
        // its nominee's claim it is following. The members are leaving for that
        // successor, and a fresh snapshot from us is exactly what makes the
        // ones still deciding refuse the claim.
        if db
            .channel_handoff_commit(&ch.channel_id)
            .ok()
            .flatten()
            .is_some_and(|commit| commit.claimed || commit.nominee.is_empty())
        {
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
        // Again now that the row is read: a rotation begun since the check
        // above may have stored its epoch in what was just read.
        if room_rotating(&ch.channel_id) {
            undo_owned_rotation(db, &ch.channel_id, rotated);
            continue;
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
                // On every republish, so a member who was offline for a rename
                // still catches up — and so this snapshot is where a device
                // restored from a backup learns the name of a room it owns,
                // which nothing else it can ask holds for a private room.
                // Held back only while the name here is a stand-in a recovery
                // put in, which must not rename the room for everyone.
                room_name: (!db.channel_name_unconfirmed(&ch.channel_id).unwrap_or(true))
                    .then(|| ch.name.clone()),
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
        let Some(publish_id) = start_own_channel_publish(state, record) else {
            undo_owned_rotation(db, &ch.channel_id, rotated);
            continue;
        };
        {
            state.channel_moderation_publish_at.insert(channel_id, now);
            // The ban is now an eviction: the snapshot naming the new epoch is
            // on its way, and the re-seal at the end of this pass reaches
            // everyone still entitled to it.
            // Its commitment goes out on the settings pass that follows this
            // one in the same tick: storing the epoch moved the room's key
            // generation.
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
            // stops this loop on its own. Not with a recovery's stand-in name,
            // which a registry whose real claim has lapsed would then take.
            if !settings.rendezvous_url.is_empty()
                && !db.channel_name_unconfirmed(&ch.channel_id).unwrap_or(true)
            {
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
            // and 6h against a 24h TTL survives a missed pass. Not while the
            // name is a recovery's stand-in, which Discover would then list.
            if !private && !db.channel_name_unconfirmed(&ch.channel_id).unwrap_or(true) {
                let index = ember::dht::publish::SignedRecord::channel_index(
                    &ch.name,
                    channel_id,
                    ident.pubkey,
                    false,
                    Some(ch.language.as_str()).filter(|l| !l.is_empty()),
                    &ident.signing_key,
                );
                if let Some(index_id) = start_own_channel_publish(state, index) {
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

/// The key for a room this identity is about to own: created, handed over to
/// us, or claimed. Returns whether it was derived from the identity, so the
/// caller can derive the rest of the room's keys the same way.
///
/// Derived from the identity and a fresh random salt (see
/// [`ember::channel::derive_owned_room_seed`]), with the salt written down
/// before the room is published: that is what the identity's owned-rooms list
/// carries, and what lets the room be found again from the identity alone. A
/// salt that cannot be written gives a random key instead, which works the
/// same but only comes back with a backup taken after it.
pub(crate) fn mint_owned_room_identity(
    db: &Database,
    identity_seed: &[u8; 32],
) -> (ember::channel::ChannelIdentity, bool) {
    let salt = ember::channel::generate_owned_room_salt();
    let ident = ember::channel::ChannelIdentity::from_seed(
        &ember::channel::derive_owned_room_seed(identity_seed, &salt),
    );
    match db.record_channel_owned_salt(&hex::encode(ident.channel_id), &salt) {
        Ok(()) => (ident, true),
        Err(e) => {
            debug!("Ember channel: could not record a room salt, using a random key: {e}");
            (ember::channel::ChannelIdentity::generate(), false)
        }
    }
}

/// Whether the identity's owned-rooms list on the network has been read into
/// the database since this launch. Held in memory, not in the database: a
/// database copied back by hand, or by the system's own restore, carries
/// whatever the database said, and an old one would publish its list over a
/// newer one naming rooms made since.
static OWNED_ROOMS_LIST_READ: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn owned_rooms_list_read() -> bool {
    OWNED_ROOMS_LIST_READ.load(std::sync::atomic::Ordering::Acquire)
}

pub(crate) fn note_owned_rooms_list_read() {
    OWNED_ROOMS_LIST_READ.store(true, std::sync::atomic::Ordering::Release);
}

/// When the latest look at the network's owned-rooms list that has ended
/// began, as Unix seconds; 0 before one has ended this launch. A look that
/// failed counts: a publish waits on one, not on its success.
static OWNED_ROOMS_READ_BEGAN_AT: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// When a publish of the owned-rooms list began waiting on a look, as Unix
/// seconds; 0 when none is waiting. One older than
/// [`OWNED_ROOMS_READ_WAIT_SECS`] plus [`OWNED_ROOMS_READ_FRESH_SECS`] counts
/// as none ([`live_owned_rooms_ask`]).
static OWNED_ROOMS_READ_ASKED_AT: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// How recent a look has to be for the list to go out on it. The read loop
/// looks ten minutes ahead of a scheduled publish, and a look walks every
/// listed room, which takes minutes of its own.
const OWNED_ROOMS_READ_FRESH_SECS: i64 = 15 * 60;

/// The longest a publish waits on a look it asked for that never ends: the
/// read loop may not be running.
const OWNED_ROOMS_READ_WAIT_SECS: i64 = 10 * 60;

/// Note that a look at the network's owned-rooms list that began at
/// `began_at` has ended, however it ended.
pub(crate) fn note_owned_rooms_read_ended(began_at: i64) {
    OWNED_ROOMS_READ_BEGAN_AT.fetch_max(began_at, std::sync::atomic::Ordering::AcqRel);
}

/// Woken when a publish of the owned-rooms list waits on a look; the read
/// loop looks at once (`channel_recovery`).
pub(crate) fn owned_rooms_read_wanted() -> &'static tokio::sync::Notify {
    static WANTED: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();
    WANTED.get_or_init(tokio::sync::Notify::new)
}

/// Whether a publish of the owned-rooms list waits for a look at the
/// network's copy, given when the latest look that ended began (`read_began`),
/// when this publish asked for one (`asked`; 0 for not yet) and `now`.
///
/// Storers keep one list per identity, so a publish replaces whatever the
/// identity's other device last published there. Going out only after a
/// recent look — one that carried what that device added — is what keeps a
/// room made there from being dropped. A look counts when it began within
/// [`OWNED_ROOMS_READ_FRESH_SECS`], so one the publish asked for counts as
/// soon as it ends, read or not; one that has not ended is waited on for
/// [`OWNED_ROOMS_READ_WAIT_SECS`].
pub(crate) fn owned_rooms_publish_waits(read_began: i64, asked: i64, now: i64) -> bool {
    if owned_rooms_read_fresh(read_began, now) {
        return false;
    }
    let asked = live_owned_rooms_ask(asked, now);
    !(asked > 0 && now - asked >= OWNED_ROOMS_READ_WAIT_SECS)
}

/// Whether a look that began at `read_began` (0 for none) is recent enough
/// at `now` for the owned-rooms list to go out on it.
fn owned_rooms_read_fresh(read_began: i64, now: i64) -> bool {
    read_began > 0 && now - read_began <= OWNED_ROOMS_READ_FRESH_SECS
}

/// `asked`, or 0 when it is too old to be the ask of a publish still
/// waiting: a publish goes once [`OWNED_ROOMS_READ_WAIT_SECS`] have passed,
/// so an ask that outlived that by [`OWNED_ROOMS_READ_FRESH_SECS`] was left
/// by one that never went, and a publish now asks again.
fn live_owned_rooms_ask(asked: i64, now: i64) -> i64 {
    if asked > 0 && now - asked < OWNED_ROOMS_READ_WAIT_SECS + OWNED_ROOMS_READ_FRESH_SECS {
        asked
    } else {
        0
    }
}

/// Whether the read loop, woken by a publish of the owned-rooms list
/// ([`owned_rooms_read_wanted`]), still has to look at `now`. It does not
/// when a look recent enough for the publish has ended since the publish
/// asked, as one already under way when it asked does.
pub(crate) fn owned_rooms_read_still_wanted(now: i64) -> bool {
    !owned_rooms_read_fresh(OWNED_ROOMS_READ_BEGAN_AT.load(std::sync::atomic::Ordering::Acquire), now)
}

/// Whether a publish of the owned-rooms list goes out at `now`, given whether
/// one is due (`due`). One due waits while [`owned_rooms_publish_waits`]
/// says so, asking the read loop for a look the first time; the ask is
/// dropped once the list goes out or is no longer due.
fn owned_rooms_publish_gate(due: bool, now: i64) -> bool {
    use std::sync::atomic::Ordering;
    if !due {
        OWNED_ROOMS_READ_ASKED_AT.store(0, Ordering::Release);
        return false;
    }
    let asked = live_owned_rooms_ask(OWNED_ROOMS_READ_ASKED_AT.load(Ordering::Acquire), now);
    if owned_rooms_publish_waits(OWNED_ROOMS_READ_BEGAN_AT.load(Ordering::Acquire), asked, now) {
        if asked == 0 {
            OWNED_ROOMS_READ_ASKED_AT.store(now, Ordering::Release);
            owned_rooms_read_wanted().notify_one();
        }
        return false;
    }
    OWNED_ROOMS_READ_ASKED_AT.store(0, Ordering::Release);
    true
}

#[cfg(test)]
pub(crate) fn owned_rooms_read_began_at() -> i64 {
    OWNED_ROOMS_READ_BEGAN_AT.load(std::sync::atomic::Ordering::Acquire)
}

/// Held by every test that reads or moves the process-wide look and ask
/// times, which tests running in parallel would otherwise move under it.
#[cfg(test)]
pub(crate) fn owned_rooms_read_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// No look ended and no publish waiting, as at launch. Only under
/// [`owned_rooms_read_test_lock`].
#[cfg(test)]
pub(crate) fn reset_owned_rooms_read_times() {
    OWNED_ROOMS_READ_BEGAN_AT.store(0, std::sync::atomic::Ordering::Release);
    OWNED_ROOMS_READ_ASKED_AT.store(0, std::sync::atomic::Ordering::Release);
}

#[cfg(test)]
fn owned_rooms_read_asked_at() -> i64 {
    OWNED_ROOMS_READ_ASKED_AT.load(std::sync::atomic::Ordering::Acquire)
}

/// When this device next publishes its owned-rooms list, as Unix seconds; 0
/// before its first publish this launch.
static NEXT_OWNED_ROOMS_PUBLISH_AT: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// When this device next publishes its owned-rooms list, so a read of the
/// network's can come just before it. `None` until it has published once.
pub(crate) fn next_owned_rooms_list_publish_at() -> Option<i64> {
    let at = NEXT_OWNED_ROOMS_PUBLISH_AT.load(std::sync::atomic::Ordering::Acquire);
    (at > 0).then_some(at)
}

/// Rooms a recovery is putting back right now. Between the row going in and
/// the room's snapshot landing on it, the owner loop would otherwise sign a
/// snapshot of a room with no bans, no topic and an old key, and that
/// snapshot, being newer, would then outrank the real one.
fn rooms_being_restored() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    static ROOMS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    ROOMS.get_or_init(Default::default)
}

pub(crate) fn room_being_restored(channel_id: &str) -> bool {
    rooms_being_restored()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(channel_id)
}

/// Held while a recovery puts a room back; the room is let go when dropped.
pub(crate) struct RestoringRoom(String);

impl RestoringRoom {
    pub(crate) fn begin(channel_id: &str) -> Self {
        rooms_being_restored()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(channel_id.to_string());
        Self(channel_id.to_string())
    }
}

impl Drop for RestoringRoom {
    fn drop(&mut self) {
        rooms_being_restored()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

/// Rooms of ours with a rotated key stored whose snapshot has not committed
/// yet, and so may still be taken back, by how many rotations. A settings
/// record signed meanwhile would commit the room to a key it then undoes
/// ([`read_owned_channel_settings`]).
fn rooms_rotating() -> &'static std::sync::Mutex<HashMap<String, usize>> {
    static ROOMS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, usize>>> = std::sync::OnceLock::new();
    ROOMS.get_or_init(Default::default)
}

fn room_rotating(channel_id: &str) -> bool {
    rooms_rotating()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(channel_id)
}

/// Whether the owner loop signs nothing for a room of ours this pass.
///
/// Recovered, and still without the key the room seals with: a snapshot from
/// here would announce an older one, and a rotation would mint a key under a
/// number the room already uses. The key-epoch loop fetches our own sealed
/// copy and lifts this.
///
/// Rotating ([`RotatingRoom`]): the new epoch is stored before the snapshot
/// that announces it commits, so a snapshot from here would announce it and
/// the re-seal after it would hand its key to every member, and a rotation
/// taken back then leaves the members on a key the owner no longer uses.
fn owner_republish_held_back(db: &Database, channel_id: &str) -> bool {
    room_being_restored(channel_id)
        || room_rotating(channel_id)
        || db.channel_owner_key_pending(channel_id).ok().flatten().is_some()
}

/// Held from before a rotation stores its key until its snapshot has
/// committed or the rotation has been taken back. Dropping it moves the
/// room's key generation, so a settings pass the rotation held back reads the
/// room again at once.
pub(crate) struct RotatingRoom(String);

impl RotatingRoom {
    pub(crate) fn begin(channel_id: &str) -> Self {
        *rooms_rotating()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(channel_id.to_string())
            .or_default() += 1;
        Self(channel_id.to_string())
    }
}

impl Drop for RotatingRoom {
    fn drop(&mut self) {
        {
            let mut rooms = rooms_rotating().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(count) = rooms.get_mut(&self.0) {
                *count -= 1;
                if *count == 0 {
                    rooms.remove(&self.0);
                }
            }
        }
        crate::storage::database::bump_channel_key_generation(&self.0);
    }
}

/// Keep the identity's owned-rooms list on the network: on the owner records'
/// cadence, and as soon as the set of rooms changes, so a room made or taken
/// over is in it within minutes rather than within six hours.
///
/// Only once the network's list has been read this launch (see
/// [`owned_rooms_list_read`]): a database from an older time would otherwise
/// replace a list naming the rooms made since with one that does not. And
/// each time only after a recent look at it ([`owned_rooms_publish_waits`]),
/// which this asks for when there has been none. An empty list is published
/// too, so a deleted last room stops being listed.
pub(super) async fn maybe_publish_owned_rooms_list(
    socket: &UdpSocket,
    state: &mut NetworkState,
    db: &Arc<Database>,
    identity: &crate::storage::identity::NodeIdentity,
) {
    if !owned_rooms_list_read() {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    if db.chat_locked() {
        owned_rooms_publish_gate(false, now);
        return;
    }
    // `Some(unchanged)` when `salts` are due out.
    let due = |state: &NetworkState, salts: &[ember::channel::OwnedRoomSalt]| {
        let unchanged = state.owned_rooms_published.as_deref() == Some(salts);
        (!unchanged
            || ember::channel::schedule_due(
                state.owned_rooms_published_at,
                now,
                ember::channel::MODERATION_REPUBLISH_SECS,
            ))
        .then_some(unchanged)
    };
    let due_now = db.owned_room_salts().is_ok_and(|salts| due(state, &salts).is_some());
    if !owned_rooms_publish_gate(due_now, now) {
        return;
    }
    // Read again: the look stored what it carried.
    let Ok(salts) = db.owned_room_salts() else {
        return;
    };
    let Some(unchanged) = due(state, &salts) else {
        return;
    };
    let signing = crate::network::ember::crypto::signing_key_from_bytes(&identity.ed25519_secret_key);
    let listed = if ember::channel::PAD_OWNED_ROOMS_LIST {
        ember::channel::pad_owned_rooms_list(&salts, &identity.ed25519_secret_key)
    } else {
        salts.clone()
    };
    // `owned_room_salts` stops at what one list carries, and padding never
    // goes past it, so this only fails if the identity key itself is unusable.
    let Some(record) = ember::dht::publish::SignedRecord::owned_rooms(&listed, &signing) else {
        warn!("Ember: could not sign this identity's list of owned rooms");
        return;
    };
    if let Some(publish_id) = start_own_channel_publish(state, record) {
        // A changed list goes out once more within the hour: starting a store
        // is not its landing, and a list that missed would leave a new room
        // unfindable until the next six-hourly pass.
        state.owned_rooms_published_at = if unchanged {
            now
        } else {
            now - ember::channel::MODERATION_REPUBLISH_SECS + OWNED_ROOMS_CONFIRM_SECS
        };
        NEXT_OWNED_ROOMS_PUBLISH_AT.store(
            state.owned_rooms_published_at + ember::channel::MODERATION_REPUBLISH_SECS,
            std::sync::atomic::Ordering::Release,
        );
        state.owned_rooms_published = Some(salts);
        drive_ember_publish(socket, state, publish_id).await;
    }
}

/// How soon a changed owned-rooms list is published again.
const OWNED_ROOMS_CONFIRM_SECS: i64 = 30 * 60;

/// How soon a changed settings record is published again, for the same reason
/// as [`OWNED_ROOMS_CONFIRM_SECS`].
const CHANNEL_SETTINGS_CONFIRM_SECS: i64 = OWNED_ROOMS_CONFIRM_SECS;
/// How soon a settings record that stored on no node, or could not be
/// started or read, is tried again.
const CHANNEL_SETTINGS_RETRY_SECS: i64 = 60;
/// How soon a room the owner-record gates held back is looked at again,
/// unless its keys move first. Recovery lifts the commonest gate by storing
/// the key it waited on, which moves them.
const CHANNEL_SETTINGS_HELD_BACK_SECS: i64 = 5 * 60;

/// What this device last did about one owned room's settings record.
pub(super) struct ChannelSettingsPublished {
    /// [`Database::channel_key_generation`] when the room's keys were last
    /// read. A rotation, one taken back, or any other change to the epochs
    /// moves it, so a pass reads the keys again only once it has moved or
    /// `due_at` has come.
    generation: u64,
    /// What the last record this launch committed to, as read from the
    /// epochs when it was signed; `None` until one has gone out.
    key_commitments: Option<Vec<(i64, [u8; 32])>>,
    /// When the room is read again whatever its keys do: the confirm or
    /// republish, a retry, or a held-back room's next look.
    due_at: i64,
    /// The STORE verdict while it is outstanding.
    verdict: Option<oneshot::Receiver<EmberPublishResult>>,
}

/// Whether a pass reads one owned room's keys: never read this launch, its
/// keys moved since, or its schedule has come.
fn channel_settings_read_due(published: Option<&ChannelSettingsPublished>, generation: u64, now: i64) -> bool {
    published.is_none_or(|p| p.generation != generation || now >= p.due_at)
}

/// Whether a room whose commitments read as `current` publishes, given those
/// it last published (`None`: nothing yet this launch) and whether its
/// schedule has come; and if so, how many seconds until it goes out again.
/// A change goes out at once and again within
/// [`CHANNEL_SETTINGS_CONFIRM_SECS`]; otherwise on the snapshot's cadence.
/// The first publish of a launch is a change when `current` differs from the
/// commitments of the copy held (`held`, none read as none committed): a
/// rotation committed before this pass has had no confirm.
fn channel_settings_publish_plan(
    last: Option<&[(i64, [u8; 32])]>,
    held: Option<&[(i64, [u8; 32])]>,
    current: &[(i64, [u8; 32])],
    schedule_due: bool,
) -> Option<i64> {
    match last {
        None if held.unwrap_or_default() != current => Some(CHANNEL_SETTINGS_CONFIRM_SECS),
        None => Some(ember::channel::MODERATION_REPUBLISH_SECS),
        Some(last) if last != current => Some(CHANNEL_SETTINGS_CONFIRM_SECS),
        Some(_) if schedule_due => Some(ember::channel::MODERATION_REPUBLISH_SECS),
        Some(_) => None,
    }
}

/// One owned room's settings, as read off the network task.
enum OwnedChannelSettingsRead {
    /// An owner-record gate holds the room back, or its keys may yet change
    /// under the read: a rotation not yet committed, or a write since the key
    /// generation was sampled.
    HeldBack,
    /// The room's seed or keys could not be read, or made no record.
    Unreadable,
    Read {
        key_commitments: Vec<(i64, [u8; 32])>,
        /// The record to publish, what to hold of it once it has started, and
        /// how soon it goes out again; `None` when nothing is due.
        publish: Option<Box<OwnedChannelSettingsPublish>>,
    },
}

type OwnedChannelSettingsPublish = (
    ember::dht::publish::SignedRecord,
    crate::storage::database::HeldChannelSettings,
    i64,
);

/// Read and, when [`channel_settings_publish_plan`] says so, sign one owned
/// private room's settings record. Blocking: it decrypts the room's keys.
/// Writes nothing; the record is held once its publish has started.
///
/// `generation` is the room's key generation sampled before the read. The
/// keys read commit the room only if nothing has written them since and no
/// rotation is in flight ([`RotatingRoom`]): a rotation stores its key before
/// its snapshot commits, and takes it back if the commit fails.
fn read_owned_channel_settings(
    db: &Database,
    channel_id: [u8; 16],
    generation: u64,
    last: Option<&[(i64, [u8; 32])]>,
    schedule_due: bool,
    now: i64,
) -> OwnedChannelSettingsRead {
    let channel_id_hex = hex::encode(channel_id);
    // The owner-record loop's gates, for its reasons: a recovered room still
    // without its current key would commit to an older set, and a room
    // leaving for a successor this device did not offer is not ours to keep
    // speaking for.
    if room_being_restored(&channel_id_hex)
        || db.channel_owner_key_pending(&channel_id_hex).ok().flatten().is_some()
        || db
            .channel_handoff_commit(&channel_id_hex)
            .ok()
            .flatten()
            .is_some_and(|commit| commit.claimed || commit.nominee.is_empty())
    {
        return OwnedChannelSettingsRead::HeldBack;
    }
    let Ok(Some(seed)) = db.load_channel_owner_seed(&channel_id_hex) else {
        return OwnedChannelSettingsRead::Unreadable;
    };
    let ident = ember::channel::ChannelIdentity::from_seed(&seed);
    if ident.channel_id != channel_id {
        return OwnedChannelSettingsRead::Unreadable;
    }
    let Ok(epochs) = db.load_channel_key_epochs(&channel_id_hex) else {
        return OwnedChannelSettingsRead::Unreadable;
    };
    if room_rotating(&channel_id_hex) || db.channel_key_generation(&channel_id_hex) != generation {
        return OwnedChannelSettingsRead::HeldBack;
    }
    let (key_commitments, admission) = own_channel_settings(&channel_id, &epochs);
    let held = last
        .is_none()
        .then(|| db.channel_settings(&channel_id_hex).ok().flatten())
        .flatten();
    let Some(next_in) = channel_settings_publish_plan(
        last,
        held.as_ref().map(|held| held.key_commitments.as_slice()),
        &key_commitments,
        schedule_due,
    ) else {
        return OwnedChannelSettingsRead::Read {
            key_commitments,
            publish: None,
        };
    };
    let Ok(stamp) = db.stamp_channel_settings(&channel_id_hex, now) else {
        return OwnedChannelSettingsRead::Unreadable;
    };
    let Some(record) = ember::dht::publish::SignedRecord::channel_settings_at(
        &key_commitments,
        admission.setting(),
        channel_id,
        ident.pubkey,
        true,
        &ident.signing_key,
        stamp,
    ) else {
        warn!("Ember: channel {channel_id_hex} key commitments do not make a valid settings record");
        return OwnedChannelSettingsRead::Unreadable;
    };
    let held = crate::storage::database::HeldChannelSettings {
        signed_at: stamp,
        signature: record.signature,
        key_commitments: key_commitments.clone(),
        admission: admission.setting(),
    };
    OwnedChannelSettingsRead::Read {
        key_commitments,
        publish: Some(Box::new((record, held, next_in))),
    }
}

/// Whether this device publishes a settings record for `ch`: every private
/// room it owns and still runs, rotated or not, since each states its
/// admission rule. A public room has no setting yet, so it publishes nothing.
fn owner_publishes_channel_settings(ch: &crate::storage::database::StoredChannel) -> bool {
    !ch.deleted
        && ch.is_owner
        && ch.successor_id.is_empty()
        && ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE
}

/// What an owner's settings record for one of its private rooms says: the
/// commitments to each rotated epoch among `epochs` (newest first, as
/// `load_channel_key_epochs` reads them), and its admission rule. Epoch 0 is
/// the key the room's first invites were minted with and has no commitment.
fn own_channel_settings(
    channel_id: &[u8; 16],
    epochs: &[(i64, [u8; 32])],
) -> (Vec<(i64, [u8; 32])>, ember::channel::RosterAdmission) {
    let key_commitments = epochs
        .iter()
        .filter(|(epoch, _)| *epoch >= 1)
        .take(ember::dht::publish::SETTINGS_KEY_COMMITMENTS_MAX)
        .map(|(epoch, secret)| {
            (
                *epoch,
                ember::channel::key_commitment(channel_id, *epoch, &ember::channel::content_key(secret)),
            )
        })
        .collect();
    (key_commitments, ember::channel::RosterAdmission::OWNED_PRIVATE_ROOM)
}

/// Keep each owned private room's settings record on the network: the key
/// commitments of every epoch the room keeps, and its admission rule.
///
/// Published as soon as the commitments differ from those last published,
/// which is after every rotation and every rotation taken back (a rotation
/// committed from a command asks for a pass at once), then once more within
/// [`CHANNEL_SETTINGS_CONFIRM_SECS`], and otherwise on the snapshot's cadence,
/// [`ember::channel::MODERATION_REPUBLISH_SECS`]; the first of a launch is
/// confirmed the same way when it differs from the copy held. One that stored
/// on no node is tried again within a minute. A room that has never rotated
/// publishes one too, with no commitments, so commitments a room no longer
/// stands behind are taken back the same way. Nothing is signed for a room
/// while a rotation of it is in flight ([`RotatingRoom`]), so no record
/// commits to a key that is then taken back.
///
/// A room's keys are read, on the blocking pool, only when its key generation
/// has moved or its schedule has come ([`channel_settings_read_due`]), so a
/// settled room costs a pass no database work at all, and a room the gates
/// hold back is looked at again only after [`CHANNEL_SETTINGS_HELD_BACK_SECS`].
pub(super) async fn maybe_publish_channel_settings(
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
    for published in state.channel_settings_published.values_mut() {
        let Some(verdict) = published.verdict.as_mut() else {
            continue;
        };
        // A dropped sender is a publish that went away without a verdict,
        // which is not evidence it landed either.
        let stored = match verdict.try_recv() {
            Ok(result) => Some(result.stored_on > 0),
            Err(oneshot::error::TryRecvError::Closed) => Some(false),
            Err(oneshot::error::TryRecvError::Empty) => None,
        };
        if let Some(stored) = stored {
            published.verdict = None;
            if !stored {
                published.due_at = published.due_at.min(now + CHANNEL_SETTINGS_RETRY_SECS);
            }
        }
    }
    let due: Vec<([u8; 16], u64, Option<Vec<(i64, [u8; 32])>>, bool)> = channels
        .iter()
        .filter(|ch| owner_publishes_channel_settings(ch))
        .filter_map(|ch| {
            let channel_id = <[u8; 16]>::try_from(hex::decode(&ch.channel_id).ok()?).ok()?;
            // Sampled before the keys are read, so a change landing while
            // they are has the next pass read them again.
            let generation = db.channel_key_generation(&ch.channel_id);
            let published = state.channel_settings_published.get(&channel_id);
            channel_settings_read_due(published, generation, now).then(|| {
                (
                    channel_id,
                    generation,
                    published.and_then(|p| p.key_commitments.clone()),
                    published.is_none_or(|p| now >= p.due_at),
                )
            })
        })
        .take(CHANNEL_MODERATION_PUBLISH_PER_TICK)
        .collect();
    if due.is_empty() {
        return;
    }
    let reads = {
        let db = db.clone();
        tokio::task::spawn_blocking(move || {
            due.into_iter()
                .map(|(channel_id, generation, last, schedule_due)| {
                    let read =
                        read_owned_channel_settings(&db, channel_id, generation, last.as_deref(), schedule_due, now);
                    (channel_id, generation, read)
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or_default()
    };
    for (channel_id, generation, read) in reads {
        let entry = state
            .channel_settings_published
            .entry(channel_id)
            .or_insert_with(|| ChannelSettingsPublished {
                generation,
                key_commitments: None,
                due_at: now,
                verdict: None,
            });
        let (key_commitments, (record, held, next_in)) = match read {
            OwnedChannelSettingsRead::HeldBack => {
                entry.generation = generation;
                entry.due_at = now + CHANNEL_SETTINGS_HELD_BACK_SECS;
                continue;
            }
            OwnedChannelSettingsRead::Unreadable => {
                entry.generation = generation;
                entry.due_at = now + CHANNEL_SETTINGS_RETRY_SECS;
                continue;
            }
            OwnedChannelSettingsRead::Read { publish: None, .. } => {
                entry.generation = generation;
                continue;
            }
            OwnedChannelSettingsRead::Read {
                key_commitments,
                publish: Some(publish),
            } => (key_commitments, *publish),
        };
        let Some(publish_id) = start_own_channel_publish(state, record) else {
            if let Some(entry) = state.channel_settings_published.get_mut(&channel_id) {
                entry.generation = generation;
                entry.due_at = now + CHANNEL_SETTINGS_RETRY_SECS;
            }
            continue;
        };
        // Held before it goes out, so the next stamp counts on from this one.
        let hold = {
            let db = db.clone();
            let channel_id_hex = hex::encode(channel_id);
            tokio::task::spawn_blocking(move || db.hold_own_channel_settings(&channel_id_hex, &held)).await
        };
        if !matches!(hold, Ok(Ok(_))) {
            debug!(
                "Ember: channel {} settings record going out without being held here",
                hex::encode(channel_id)
            );
        }
        let (tx, rx) = oneshot::channel();
        state.ember_dht_pending_publishes.insert(publish_id, tx);
        state.channel_settings_published.insert(
            channel_id,
            ChannelSettingsPublished {
                generation,
                key_commitments: Some(key_commitments),
                due_at: now + next_in,
                verdict: Some(rx),
            },
        );
        drive_ember_publish(socket, state, publish_id).await;
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
/// - a DHT presence record opened under the current key, whose extra the
///   member seals themselves and storers only hold. A v2 seal carries the
///   member's signature binding it to the record, so it cannot be moved into
///   one somebody else signs. A v1 seal names the room but not the member, so
///   a storer could copy one into a record it signs itself; v1 is still read
///   for members on 1.7.4;
/// - a beacon carrying the member's own key proof, checked against our current
///   key in [`apply_channel_presence_beacons`];
/// - unless the room's settings say [`ember::channel::RosterAdmission::KeyProven`],
///   a live chat line opened under the current key, whose seal is the author's
///   because relays forward the original body. Catch-up re-serves are sealed
///   by the responder and never admit ([`ember::channel::chat_author_joins_gossip_roster`]),
///   but their TTL can be raised in transit, which is what that rule closes.
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
    let records = {
        let db = db.clone();
        let channel_id_hex = ch.channel_id.clone();
        let epoch = ch.key_epoch;
        let ident = ident.clone();
        let our_seed = zeroize::Zeroizing::new(identity.ed25519_secret_key);
        tokio::task::spawn_blocking(move || {
            seal_current_epoch_records(&db, &channel_id_hex, epoch, &ident, &our_seed, our_pk)
        })
        .await
        .unwrap_or_default()
    };
    for record in records {
        if let Some(publish_id) = start_own_channel_publish(state, record) {
            drive_ember_publish(socket, state, publish_id).await;
        }
    }
}

/// The records [`republish_channel_key_epoch`] publishes: every form of the
/// room's `epoch` key sealed to us and to each unbanned member. Empty when
/// that key is not held. Blocking: it reads the key and the roster, and runs a
/// DH and a seal per member.
fn seal_current_epoch_records(
    db: &Database,
    channel_id_hex: &str,
    epoch: i64,
    ident: &ember::channel::ChannelIdentity,
    our_seed: &[u8; 32],
    our_pk: [u8; 32],
) -> Vec<ember::dht::publish::SignedRecord> {
    let Some(secret) = db
        .load_channel_key_epochs(channel_id_hex)
        .unwrap_or_default()
        .into_iter()
        .find(|(e, _)| *e == epoch)
        .map(|(_, secret)| zeroize::Zeroizing::new(secret))
    else {
        return Vec::new();
    };
    // Our own copy first, sealed to our own identity: it is what a device
    // restored from a backup taken before this epoch reads the key back from.
    // A member's slot, so the record is the one every member's is.
    let members = db.list_channel_members(channel_id_hex).unwrap_or_default();
    let recipients = std::iter::once(our_pk).chain(members.iter().filter_map(|member| {
        if member.banned {
            return None;
        }
        let member_pk = hex::decode(&member.member_pubkey)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())?;
        (member_pk != our_pk).then_some(member_pk)
    }));
    let mut records = Vec::new();
    for member_pk in recipients {
        let (Some(wrap), Some(blind)) = (
            ember::channel::derive_channel_epoch_secret(our_seed, &member_pk, &ident.channel_id, epoch),
            ember::channel::epoch_blind(our_seed, &member_pk, &ident.channel_id),
        ) else {
            continue;
        };
        let sealed =
            ember::channel::seal_channel_key_epoch(&wrap, &ident.channel_id, epoch, &secret);
        records.extend(ember::dht::publish::SignedRecord::channel_key_epoch_forms(
            ident.channel_id,
            ident.pubkey,
            &member_pk,
            member_pk == our_pk,
            epoch,
            &blind,
            &sealed,
            &ident.signing_key,
        ));
    }
    records
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
///
/// What to look up is read on the blocking pool, for every due room at once
/// ([`channel_epoch_lookup`]). A room with nothing to look up is stamped, so it
/// is read again an interval on rather than on every tick.
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
    let due: Vec<([u8; 16], crate::storage::database::StoredChannel)> = channels
        .iter()
        .filter(|ch| {
            // An owner mints its keys and needs none fetched — unless it is a
            // recovered owner, which fetches the current one back from the
            // copy it sealed to itself ([`channel_epoch_lookup`] asks).
            ch.in_room_now()
                && ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE
                && ch.key_epoch_wanted > 0
                && ch.successor_id.is_empty()
                && (!ch.is_owner || ch.key_epoch_wanted > ch.key_epoch)
        })
        .filter_map(|ch| {
            let channel_id = <[u8; 16]>::try_from(hex::decode(&ch.channel_id).ok()?).ok()?;
            let last = state.channel_epoch_fetch_at.get(&channel_id).copied().unwrap_or(0);
            ember::channel::schedule_due(last, now, CHANNEL_EPOCH_FETCH_SECS)
                .then(|| (channel_id, ch.clone()))
        })
        .collect();
    if due.is_empty() {
        return;
    }
    let lookups = {
        let db = db.clone();
        let our_seed = identity.ed25519_secret_key;
        let our_pk = identity.ed25519_public_key;
        tokio::task::spawn_blocking(move || {
            due.into_iter()
                .map(|(channel_id, ch)| {
                    (channel_id, channel_epoch_lookup(&db, &our_seed, &our_pk, &ch, &channel_id))
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or_default()
    };
    let mut started = 0usize;
    for (channel_id, lookup) in lookups {
        let Some((target, keys)) = lookup else {
            state.channel_epoch_fetch_at.insert(channel_id, now);
            continue;
        };
        if state
            .ember_channel_epoch_searches
            .values()
            .any(|held| *held == (channel_id, target))
        {
            state.channel_epoch_fetch_at.insert(channel_id, now);
            continue;
        }
        if started >= CHANNEL_EPOCH_FETCH_PER_TICK {
            continue;
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
                .ember_channel_epoch_searches
                .insert(search_id, (channel_id, target));
            drive_ember_search(socket, state, search_id).await;
            any = true;
        }
        if !any {
            break;
        }
        state.channel_epoch_fetch_at.insert(channel_id, now);
        started += 1;
    }
}

/// The epoch to look our own copy of a private room's content key up for, and
/// the keys to look under: v2 first, then v1. `None` when the room has nothing
/// to look up: no epoch in the retention window missing, or a room we own that
/// is not a recovered one waiting on its key.
///
/// The newest epoch we are *missing*, which is not the same as the one the
/// owner advertises. Sleeping through two rotations used to leave the
/// intermediate epoch unfetched for good: the member picked up the newest,
/// `key_epoch` caught up to `key_epoch_wanted`, and the loop stopped looking —
/// so the window of history sealed under the epoch in between stayed
/// unreadable even though its record was still in the DHT and
/// `channel_content_keys` would have used it. One indexed read of epoch
/// numbers, no secrets; blocking, so the caller runs it off the network task.
///
/// v2 needs only the owner's key, which the moderation poll brings, so it is
/// found for any epoch whatever this device missed. v1 is the only form a
/// 1.7.4 owner publishes and a 1.7.4 storer keeps.
pub(crate) fn channel_epoch_lookup(
    db: &Database,
    our_seed: &[u8; 32],
    our_pk: &[u8; 32],
    ch: &crate::storage::database::StoredChannel,
    channel_id: &[u8; 16],
) -> Option<(i64, Vec<[u8; 16]>)> {
    if ch.is_owner && db.channel_owner_key_pending(&ch.channel_id).ok().flatten().is_none() {
        return None;
    }
    let floor = (ch.key_epoch_wanted - Database::CHANNEL_KEY_EPOCHS_KEPT as i64 + 1).max(1);
    let target = db
        .newest_missing_channel_key_epoch(&ch.channel_id, floor, ch.key_epoch_wanted)
        .ok()
        .flatten()?;
    let mut keys = Vec::with_capacity(2);
    let blind = hex::decode(&ch.owner_pubkey)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|owner| ember::channel::epoch_blind(our_seed, &owner, channel_id));
    if let Some(blind) = blind {
        let member_id = ember::channel::epoch_member_id(&blind, target);
        keys.push(ember::channel::epoch_key_v2(channel_id, &member_id, target));
    }
    keys.push(ember::channel::epoch_key(channel_id, our_pk, target));
    Some((target, keys))
}

/// Hold epoch blobs until every FIND_VALUE for this room and epoch has
/// finished, v2 key and v1 key alike, then queue one ingest, so it reads the
/// two forms together.
pub(super) fn buffer_channel_epoch_records(
    state: &mut NetworkState,
    channel_id: [u8; 16],
    epoch: i64,
    records: Vec<Vec<u8>>,
) {
    state
        .ember_channel_epoch_buffer
        .entry((channel_id, epoch))
        .or_default()
        .extend(records);
    flush_channel_epoch_if_idle(state, channel_id, epoch);
}

pub(super) fn flush_channel_epoch_if_idle(state: &mut NetworkState, channel_id: [u8; 16], epoch: i64) {
    if state
        .ember_channel_epoch_searches
        .values()
        .any(|held| *held == (channel_id, epoch))
    {
        return;
    }
    if let Some(records) = state.ember_channel_epoch_buffer.remove(&(channel_id, epoch)) {
        state
            .ember_pending_channel_epoch
            .push((channel_id, epoch, records));
    }
}

/// What an epoch fetch came back with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelEpochIngest {
    /// Nothing sealed to us that this build could use.
    Nothing,
    /// The key is stored; the room is readable under it.
    Rekeyed,
    /// The owner sealed this epoch to us in an envelope version this build
    /// cannot open, and in none that it can: the room needs a newer Ember.
    NeedsNewer,
}

/// Open an epoch record sealed to us and store the key it carries.
///
/// The wrapping key is pairwise with the owner, so a blob sealed to anyone else
/// simply fails to open — which is exactly what makes a ban an eviction.
///
/// A version this build cannot open counts only when no record it can open
/// came back too: storers that predate later versions refuse them and may
/// still hold this one. They cannot both be held by one storer, which keeps a
/// single record per publisher under a key, so a later build that wants
/// members on this one to keep reading has to seal the later version under a
/// key of its own. Only the room key signs these records, so this is the
/// owner's word.
pub(crate) fn ingest_channel_epoch_records(
    db: &Database,
    identity: &crate::storage::identity::NodeIdentity,
    channel_id: [u8; 16],
    epoch: i64,
    records: &[Vec<u8>],
) -> ChannelEpochIngest {
    if db.chat_locked() {
        return ChannelEpochIngest::Nothing;
    }
    let channel_id_hex = hex::encode(channel_id);
    let Ok(Some(ch)) = db.get_channel(&channel_id_hex) else {
        return ChannelEpochIngest::Nothing;
    };
    let Some(owner_pk) = hex::decode(&ch.owner_pubkey)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    else {
        // We have not learned who owns the room, so there is nobody to derive
        // the wrapping key against yet. The moderation poll fixes that.
        return ChannelEpochIngest::Nothing;
    };
    let Some(wrap) = ember::channel::derive_channel_epoch_secret(
        &identity.ed25519_secret_key,
        &owner_pk,
        &channel_id,
        epoch,
    ) else {
        return ChannelEpochIngest::Nothing;
    };
    let mut newer_version = None;
    let mut opened_one = false;
    let our_pk = identity.ed25519_public_key;
    let our_member_id =
        ember::channel::epoch_blind(&identity.ed25519_secret_key, &owner_pk, &channel_id)
            .map(|blind| ember::channel::epoch_member_id(&blind, epoch));
    let mut records: Vec<ember::dht::publish::ChannelKeyEpochRecord> = records
        .iter()
        .filter_map(|blob| {
            ember::dht::publish::SignedRecord::parse_channel_key_epoch_record(blob, &channel_id)
        })
        .collect();
    // Newest first. A rotation rolled back and tried again under the same
    // epoch leaves two sealed keys in one slot, and a storer that missed the
    // second still serves the first; the one the owner signed last is the one
    // the room uses. Of copies signed the same second, v2 first.
    records.sort_by_key(|record| (std::cmp::Reverse(record.timestamp), !record.blinded));
    for record in records {
        let envelope = record.envelope;
        // Only our own slot, and only for the epoch we asked about. Either
        // form is self-validating about both (the parse checks the key against
        // them), so a mismatch is somebody else's.
        let ours = if record.blinded {
            our_member_id.is_some_and(|id| record.slot == id)
        } else {
            record.slot == our_pk
        };
        if !ours || record.epoch != epoch {
            continue;
        }
        if let Some(&version) = envelope.first() {
            if !ember::channel::epoch_envelope_version_supported(version) {
                newer_version = Some(version);
                continue;
            }
        }
        let Some(secret) =
            ember::channel::open_channel_key_epoch(&wrap, &channel_id, epoch, &envelope)
        else {
            continue;
        };
        opened_one = true;
        match db.insert_channel_key_epoch(&channel_id_hex, epoch, &secret) {
            Ok(()) => return ChannelEpochIngest::Rekeyed,
            Err(e) => {
                debug!("Ember channel epoch {epoch} for {channel_id_hex} not stored: {e}");
            }
        }
    }
    // A key this build opened and could not store is a local failure, not a
    // room that has moved on.
    let Some(version) = newer_version.filter(|_| !opened_one) else {
        return ChannelEpochIngest::Nothing;
    };
    match db.note_channel_newer_key(&channel_id_hex, epoch, version, chrono::Utc::now().timestamp()) {
        Ok(true) => {
            info!(
                "Ember channel {channel_id_hex}: epoch {epoch} came sealed in envelope version \
                 {version}, which needs a newer Ember"
            );
            ChannelEpochIngest::NeedsNewer
        }
        Ok(false) => ChannelEpochIngest::Nothing,
        Err(e) => {
            debug!("Ember channel {channel_id_hex}: could not note a newer key: {e}");
            ChannelEpochIngest::Nothing
        }
    }
}

pub(super) const CHANNEL_HANDOFF_FETCH_PER_TICK: usize = 2;
/// How long a nominee's successor seed keeps a room it walked out of on the
/// handoff fetch, and a forgotten room's seed on disk: as long as the old
/// room's signer republishes the record that could name it.
pub(super) const HANDOFF_SEED_FOLLOW_SECS: i64 = ember::channel::HANDOFF_RETIRED_KEEP_SECS;

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
    maybe_republish_retired_channel_handoffs(socket, state, db).await;
    let now = chrono::Utc::now().timestamp();
    let seed_horizon = now.saturating_sub(HANDOFF_SEED_FOLLOW_SECS);
    let _ = db.prune_forgotten_handoff_seeds(seed_horizon);
    let Some(channels) = channels_lite_cached(state, db) else {
        return;
    };
    // A nominee who walked out after answering an offer still holds the only
    // key to the successor the owner may have published, so its rooms are
    // still asked about until the owner stops republishing that record.
    let seeded: HashSet<String> = if channels
        .iter()
        .any(|ch| !ch.in_room && !ch.deleted && ch.successor_id.is_empty())
    {
        db.handoff_seed_rooms(seed_horizon)
            .map(|rooms| rooms.into_iter().collect())
            .unwrap_or_default()
    } else {
        HashSet::new()
    };
    let mut started = 0usize;
    for ch in channels.iter() {
        let walked_out = !ch.in_room_now();
        if walked_out && (ch.deleted || ch.is_owner || !seeded.contains(&ch.channel_id)) {
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
        if walked_out {
            continue;
        }

        // A succession claim lives under its own key, because it is signed by
        // the nominee rather than the room. Only worth asking for once the
        // owner has actually been silent long enough to honour one — and by
        // the owner, just back from such a silence, while a claim it finds can
        // still be one that silence allowed.
        let claim_due = if ch.is_owner {
            db.live_channel_owner_silence(&ch.channel_id, now)
                .ok()
                .flatten()
                .is_some()
        } else {
            !ch.successor_nominee.is_empty()
                && ch.claim_after_days > 0
                && ch.moderation_updated_at > 0
                && now.saturating_sub(ch.moderation_updated_at)
                    >= ch.claim_after_days.saturating_mul(86_400)
        };
        if !claim_due {
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

/// What a handoff fetch told us about a room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChannelHandoffIngest {
    Nothing,
    /// We followed the room to this successor.
    Followed([u8; 16]),
    /// A room we own, and no record signed by it is stored where we looked.
    OwnAbsent,
    /// A room we own, now committed to a stored record naming this successor
    /// that it was not committed to before.
    OwnAdopted([u8; 16]),
}

pub(super) fn ingest_channel_handoff_records(
    db: &Database,
    channel_id: [u8; 16],
    records: &[Vec<u8>],
) -> ChannelHandoffIngest {
    if db.chat_locked() {
        return ChannelHandoffIngest::Nothing;
    }
    let channel_id_hex = hex::encode(channel_id);
    let Ok(Some(ch)) = db.get_channel(&channel_id_hex) else {
        return ChannelHandoffIngest::Nothing;
    };
    let Ok(stored_pk) = hex::decode(&ch.pubkey) else {
        return ChannelHandoffIngest::Nothing;
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
    let Some(handoff) = best else {
        return if ch.is_owner && ch.successor_id.is_empty() {
            ChannelHandoffIngest::OwnAbsent
        } else {
            ChannelHandoffIngest::Nothing
        };
    };
    let keep = handoff.flags & ember::channel::HANDOFF_FLAG_KEEP_JOIN_SECRET != 0;
    let successor_pk = hex::encode(handoff.successor_pubkey);
    let successor_id = hex::encode(handoff.successor_channel_id);
    // Our own record, found stored — possibly one whose acknowledgement never
    // came back, or one we have since withdrawn. It is not applied here: that
    // would drop our seed before the registry name was signed over to the
    // successor. Confirming it hands the rest to `maybe_drive_channel_handoffs`,
    // which does both in order.
    if ch.is_owner {
        let held = db.channel_handoff_commit(&channel_id_hex).ok().flatten();
        let already = held.is_some_and(|held| {
            held.version == handoff.version && held.successor_pubkey.eq_ignore_ascii_case(&successor_pk)
        });
        let confirmed = db
            .confirm_channel_handoff(
                &channel_id_hex,
                handoff.version,
                &successor_pk,
                chrono::Utc::now().timestamp(),
                true,
            )
            .unwrap_or(false);
        return if confirmed && !already {
            ChannelHandoffIngest::OwnAdopted(handoff.successor_channel_id)
        } else {
            ChannelHandoffIngest::Nothing
        };
    }
    let seed = db
        .load_handoff_pending_seed(&channel_id_hex, &successor_pk, handoff.version)
        .ok()
        .flatten();
    // Asked about only because we hold a seed: a record naming some other
    // successor is not one to follow out of a room we left.
    if !ch.in_room_now() && seed.is_none() {
        return ChannelHandoffIngest::Nothing;
    }
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
        ChannelHandoffIngest::Followed(handoff.successor_channel_id)
    } else {
        ChannelHandoffIngest::Nothing
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
    if ch.is_owner {
        return follow_claim_on_owned_channel(db, &ch, channel_id, records);
    }
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
            .apply_claimed_channel_handoff(
                &channel_id_hex,
                &successor_pk_hex,
                &successor_id_hex,
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

/// Follow our nominee's claim on a room we own, made while we were silent.
///
/// The members who honoured it are in the successor already, and every
/// snapshot we publish from here makes the ones who have not yet looked refuse
/// it — so carrying on as owner splits the room. Instead the room is committed
/// to the claimed successor like a handoff of our own, which every member
/// follows however they decided on the claim, and which the handoff loop
/// publishes and then completes; the owned-room pass stops republishing it
/// meanwhile.
///
/// Judged against the silence we recorded on coming back, not our current
/// snapshot, which is newer than anything the claimant could have cited. And
/// only for a claim found within [`ember::channel::OWNER_RETURN_CLAIM_WINDOW_SECS`]
/// of that return, in a copy signed before it: nothing the claimant signs can
/// show when a claim was first made, so its turning up at once, dated inside
/// the silence, is the evidence there is that it was made then.
fn follow_claim_on_owned_channel(
    db: &Database,
    ch: &crate::storage::database::StoredChannel,
    channel_id: [u8; 16],
    records: &[Vec<u8>],
) -> Option<[u8; 16]> {
    if ch.deleted || !ch.successor_id.is_empty() {
        return None;
    }
    let now = chrono::Utc::now().timestamp();
    let silence = db.live_channel_owner_silence(&ch.channel_id, now).ok().flatten()?;
    let mut candidates: Vec<([u8; 32], [u8; 32], [u8; 16], i64, bool)> = records
        .iter()
        .filter_map(|blob| {
            ember::dht::publish::SignedRecord::parse_channel_succession_claim_signed(blob, &channel_id)
        })
        .filter(|(_, signed_at)| *signed_at <= silence.silent_until)
        .map(|(claim, _)| claim)
        .filter(|(claimant, ..)| silence.nominee.eq_ignore_ascii_case(&hex::encode(claimant)))
        .filter(|(_, _, _, witnessed_ts, _)| {
            ember::channel::claim_fits_owner_silence(
                *witnessed_ts,
                silence.silent_from,
                silence.silent_until,
                silence.claim_after_days,
            )
        })
        .collect();
    // The members' own order, so we follow the claim they did.
    candidates.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| a.2.cmp(&b.2)));
    for (claimant, successor_pk, successor_id, _, _) in candidates {
        if db
            .commit_claimed_channel_handoff(
                &ch.channel_id,
                &hex::encode(claimant),
                &hex::encode(successor_pk),
                now,
            )
            .unwrap_or(false)
        {
            tracing::info!(
                channel_id = %ch.channel_id,
                "our nominee claimed this room while we were away; following it"
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
    /// Noise keys to cache for admitted members, or `None` to forget a leaver's.
    pub(super) noise_keys: Vec<([u8; 32], Option<[u8; 32]>)>,
    /// Members whose last_seen alone moved, for the next presence emit.
    pub(super) touched: Vec<([u8; 32], i64)>,
}

impl ChannelPresenceIngest {
    /// The part of an ingest that lives in [`NetworkState`], which the database
    /// half runs without so it can leave the network loop.
    pub(super) fn apply(&self, state: &mut NetworkState, channel_id: [u8; 16]) {
        for (publisher, noise_pub) in &self.noise_keys {
            match noise_pub {
                Some(key) => {
                    state.ember_channel_noise_keys.insert(*publisher, *key);
                }
                None => {
                    state.ember_channel_noise_keys.remove(publisher);
                }
            }
        }
        for (member, at) in &self.touched {
            mark_channel_presence_dirty(state, channel_id, member, *at);
        }
    }
}

/// The newest record per member among one room's presence blobs, and the
/// members with at least one record sealed under the current secret, the head
/// of `join_secrets`.
///
/// Only the latter may be added to the roster: a retired key is also what a
/// rotation's evicted member holds, and a record under one from a key the
/// roster has never seen is that member under a new name.
///
/// Current and previous epoch are two FIND_VALUE walks. Newest-wins has to see
/// both before any row is written, or a prev-epoch live announce re-inserts
/// after the current tombstone and a prev-epoch tombstone deletes a rejoiner.
/// Equal timestamps prefer the leave.
///
/// A private room's blob is read as v2 first, under each secret, and as v1 only
/// if it is not v2. Both forms of one announcement carry one stamp and name one
/// member, so they merge as one; v2 goes in last, so of two copies signed the
/// same second the v2 one is what stands. A v2 record whose binding does not
/// verify is dropped, never read as v1.
pub(super) fn merge_channel_presence_blobs(
    records: &[Vec<u8>],
    channel_id: &[u8; 16],
    join_secrets: &[[u8; 32]],
    private: bool,
    now: i64,
) -> (
    HashMap<[u8; 32], ember::dht::publish::ChannelPresenceMember>,
    HashSet<[u8; 32]>,
) {
    use ember::dht::publish::SignedRecord;
    let content_keys: Vec<[u8; 32]> =
        join_secrets.iter().map(ember::channel::content_key).collect();
    let blinds: Vec<([u8; 16], [u8; 32])> = if private {
        join_secrets
            .iter()
            .map(|secret| ember::channel::presence_room_blind(channel_id, secret))
            .collect()
    } else {
        Vec::new()
    };
    let mut v1 = Vec::new();
    let mut v2 = Vec::new();
    for blob in records {
        let blinded = join_secrets
            .iter()
            .zip(&blinds)
            .enumerate()
            .find_map(|(index, (secret, blind))| {
                // Same rule as `open_with_content_keys`: only the head is current.
                let opened = if index == 0 {
                    ember::channel::OpenedUnder::Current
                } else {
                    ember::channel::OpenedUnder::Retired
                };
                if blob.get(17..33) == Some(&blind.0[..]) {
                    Some(
                        SignedRecord::parse_channel_presence_member_v2(blob, channel_id, secret, blind)
                            .map(|member| (member, opened)),
                    )
                } else {
                    None
                }
            });
        match blinded {
            Some(Some(found)) => v2.push(found),
            Some(None) => {}
            None => {
                if let Some(found) = ember::channel::open_with_content_keys(&content_keys, |candidate| {
                    SignedRecord::parse_channel_presence_member_in_room(
                        blob,
                        channel_id,
                        Some(candidate),
                        private,
                    )
                }) {
                    v1.push(found);
                }
            }
        }
    }
    let mut latest = HashMap::new();
    let mut current = HashSet::new();
    for (member, opened) in v1.into_iter().chain(v2) {
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
    (latest, current)
}

pub(super) fn ingest_channel_presence_records(
    db: &Database,
    our_pubkey: &[u8; 32],
    channel_id: [u8; 16],
    records: &[Vec<u8>],
) -> ChannelPresenceIngest {
    let mut outcome = ChannelPresenceIngest {
        new_neighbors: false,
        roster_changed: false,
        noise_keys: Vec::new(),
        touched: Vec::new(),
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
    let join_secrets = channel_join_secrets(db, &ch);
    let now = chrono::Utc::now().timestamp();
    let (latest, current) = merge_channel_presence_blobs(
        records,
        &channel_id,
        &join_secrets,
        ch.visibility == ember::channel::CHANNEL_KIND_PRIVATE,
        now,
    );
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
            outcome.noise_keys.push((member.publisher_key, None));
            continue;
        }
        if !current.contains(&member.publisher_key)
            && !matches!(db.channel_member_status(&channel_id_hex, &pk_hex), Ok(Some(_)))
        {
            continue;
        }
        let nick = crate::security::sanitize_display_name(&member.nickname);
        // Our own row's language comes from our settings. A walk can still
        // return the copy published before a change, and taking it would flip
        // the flag back until the new one is found.
        let language = (member.publisher_key != *our_pubkey).then(|| member.language.unwrap_or(""));
        if let Ok(write) = db.upsert_channel_member_with_language(
            &channel_id_hex,
            &pk_hex,
            &nick,
            language,
            member.timestamp,
            Some(&our_hex),
        ) {
            // A refused newcomer holds no row, so it gets no key cached
            // either: that map is sized to the rosters it serves.
            if write == ChannelMemberWrite::Refused {
                continue;
            }
            outcome
                .noise_keys
                .push((member.publisher_key, Some(member.noise_pub)));
            match write {
                ChannelMemberWrite::Inserted => {
                    if member.publisher_key != *our_pubkey {
                        outcome.new_neighbors = true;
                    }
                    outcome.roster_changed = true;
                }
                // The nickname or language moved, so the row has to be re-read
                // to be drawn.
                ChannelMemberWrite::Updated => {
                    outcome.roster_changed = true;
                }
                // A routine republish from somebody already on the list. One
                // number changed, and it goes out as that rather than as a
                // reason to rebuild the room's whole roster. `member.timestamp`
                // was clamped when the batch was merged.
                ChannelMemberWrite::Touched => {
                    if member.publisher_key != *our_pubkey {
                        outcome.touched.push((member.publisher_key, member.timestamp));
                    }
                }
                ChannelMemberWrite::Unchanged | ChannelMemberWrite::Refused => {}
            }
        }
    }
    outcome
}

/// Room lookup results waiting to be written, taken off [`NetworkState`] in one
/// go so the writes can run away from the network loop.
#[derive(Default)]
pub(super) struct ChannelIngestBatch {
    pub(super) presence: Vec<([u8; 16], Vec<Vec<u8>>)>,
    pub(super) moderation: Vec<([u8; 16], Vec<Vec<u8>>, usize)>,
    pub(super) settings: Vec<([u8; 16], Vec<Vec<u8>>)>,
    pub(super) claim: Vec<([u8; 16], Vec<Vec<u8>>)>,
    pub(super) epoch: Vec<([u8; 16], i64, Vec<Vec<u8>>)>,
    pub(super) handoff: Vec<([u8; 16], Vec<Vec<u8>>)>,
}

impl ChannelIngestBatch {
    /// Everything queued, or `None` when nothing is.
    pub(super) fn take(state: &mut NetworkState) -> Option<Self> {
        let batch = Self {
            presence: std::mem::take(&mut state.ember_pending_channel_presence),
            moderation: std::mem::take(&mut state.ember_pending_channel_moderation),
            settings: std::mem::take(&mut state.ember_pending_channel_settings),
            claim: std::mem::take(&mut state.ember_pending_channel_claim),
            epoch: std::mem::take(&mut state.ember_pending_channel_epoch),
            handoff: std::mem::take(&mut state.ember_pending_channel_handoff),
        };
        let empty = batch.presence.is_empty()
            && batch.moderation.is_empty()
            && batch.settings.is_empty()
            && batch.claim.is_empty()
            && batch.epoch.is_empty()
            && batch.handoff.is_empty();
        (!empty).then_some(batch)
    }
}

/// What a [`ChannelIngestBatch`] changed, for the network loop to act on.
#[derive(Default)]
pub(super) struct ChannelIngestResults {
    pub(super) presence: Vec<([u8; 16], ChannelPresenceIngest)>,
    /// Rooms whose moderation snapshot landed.
    pub(super) moderated: Vec<[u8; 16]>,
    /// Rooms whose settings record is looked up at once for its commitments
    /// ([`settings_owed_after_pass`]).
    pub(super) settings_owed: Vec<[u8; 16]>,
    /// `(room, successor)` for each ownership claim applied.
    pub(super) claimed: Vec<([u8; 16], [u8; 16])>,
    /// Rooms whose keys changed: readable under a new epoch, or a held key
    /// dropped because the owner's commitments contradict it.
    pub(super) rekeyed: Vec<[u8; 16]>,
    /// Rooms whose new epoch was sealed to us in a version that needs a
    /// newer Ember.
    pub(super) needs_newer: Vec<[u8; 16]>,
    /// `(room, successor)` for each handoff followed.
    pub(super) followed: Vec<([u8; 16], [u8; 16])>,
    /// `(room, successor)` for each room we own committed to a stored record
    /// of ours it was not committed to.
    pub(super) adopted: Vec<([u8; 16], [u8; 16])>,
    /// Rooms we own whose handoff fetch found no record of ours.
    pub(super) handoff_absent: Vec<[u8; 16]>,
}

/// Apply a batch to the database. Blocking: every step takes the database lock.
pub(super) fn run_channel_ingest(
    db: &Database,
    identity: &crate::storage::identity::NodeIdentity,
    our_pubkey: &[u8; 32],
    batch: ChannelIngestBatch,
) -> ChannelIngestResults {
    let mut results = ChannelIngestResults::default();
    for (channel_id, records) in batch.presence {
        let ingest = ingest_channel_presence_records(db, our_pubkey, channel_id, &records);
        results.presence.push((channel_id, ingest));
    }
    let checked_at = chrono::Utc::now().timestamp();
    if !batch.moderation.is_empty() {
        let mut backoff = settings_lookup_backoff().lock().unwrap_or_else(|e| e.into_inner());
        backoff.retain_rooms(|room| match db.get_channel_lite(&hex::encode(room)) {
            Ok(Some(ch)) => !ch.deleted,
            Ok(None) => false,
            Err(_) => true,
        });
    }
    for (channel_id, records, answered) in batch.moderation {
        // Only a search some peer actually answered counts as having looked.
        // Finding no owner record because nobody replied is not evidence the
        // owner has gone, and succession is the one feature that acts on
        // absence.
        let channel_id_hex = hex::encode(channel_id);
        if answered > 0 {
            let _ = db.touch_channel_moderation_checked(&channel_id_hex, checked_at);
        }
        let before = db.get_channel_lite(&channel_id_hex).ok().flatten();
        let applied = ingest_channel_moderation_records(db, channel_id, &records);
        if applied {
            results.moderated.push(channel_id);
        }
        let mut check_held = false;
        if let Ok(Some(row)) = db.get_channel_lite(&channel_id_hex) {
            let held = (row.key_epoch_wanted > row.key_epoch)
                .then(|| db.channel_settings(&channel_id_hex).ok().flatten())
                .flatten();
            let owed = settings_owed_after_pass(before.as_ref().map(|ch| ch.key_epoch_wanted), &row, held.as_ref());
            let ask = {
                let mut backoff = settings_lookup_backoff().lock().unwrap_or_else(|e| e.into_inner());
                if owed {
                    settings_lookup_backoff_allows(&mut backoff, channel_id, (row.key_epoch_wanted, row.key_epoch), checked_at)
                } else {
                    backoff.forget(&channel_id);
                    false
                }
            };
            if ask {
                results.settings_owed.push(channel_id);
            }
            check_held = moderation_pass_rechecks_keys(applied, before.as_ref(), &row);
        }
        if settle_channel_keys(db, channel_id, check_held) {
            results.rekeyed.push(channel_id);
        }
    }
    for (channel_id, records) in batch.settings {
        let landed = ingest_channel_settings_records(db, channel_id, &records);
        if landed {
            settings_lookup_backoff()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .forget(&channel_id);
        }
        if settle_channel_keys(db, channel_id, landed) {
            results.rekeyed.push(channel_id);
        }
    }
    for (channel_id, records) in batch.claim {
        if let Some(successor) = ingest_channel_claim_records(db, channel_id, &records) {
            results.claimed.push((channel_id, successor));
        }
    }
    for (channel_id, epoch, records) in batch.epoch {
        match ingest_channel_epoch_records(db, identity, channel_id, epoch, &records) {
            ChannelEpochIngest::Nothing => {}
            ChannelEpochIngest::Rekeyed => results.rekeyed.push(channel_id),
            ChannelEpochIngest::NeedsNewer => results.needs_newer.push(channel_id),
        }
    }
    for (channel_id, records) in batch.handoff {
        match ingest_channel_handoff_records(db, channel_id, &records) {
            ChannelHandoffIngest::Nothing => {}
            ChannelHandoffIngest::Followed(successor) => results.followed.push((channel_id, successor)),
            ChannelHandoffIngest::OwnAbsent => results.handoff_absent.push(channel_id),
            ChannelHandoffIngest::OwnAdopted(successor) => results.adopted.push((channel_id, successor)),
        }
    }
    results
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
