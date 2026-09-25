//! Unit tests for the network task's parent-module helpers.

use super::ember_publish::{EmberQueuedRecord, EMBER_MAX_CARRY_OVER_PER_PEER};
use super::*;

/// The server log is held here so the frontend can ask for it back. It has
/// to survive a reload of the webview, which wipes the store that used to
/// be the only copy — and the uploads pane was offering the webview's own
/// Reload as its context menu, so users were hitting exactly that.
///
/// One test rather than several: the buffer is process-global, and nothing
/// else in the suite writes to it, so this owns it for the duration.
#[test]
fn the_server_log_replays_its_last_lines_and_forgets_them_when_cleared() {
    clear_server_log_history();
    assert!(server_log_history().is_empty());

    let first = record_server_log("connecting");
    let second = record_server_log("connected");
    assert!(
        second.seq > first.seq,
        "sequence numbers order the replay and identify a line the \
         frontend is already holding, so they have to keep rising"
    );

    let history = server_log_history();
    assert_eq!(
        history.iter().map(|l| l.message.as_str()).collect::<Vec<_>>(),
        ["connecting", "connected"],
        "replayed oldest first, the order the view reads in"
    );
    assert_eq!(history[0].seq, first.seq);
    assert_eq!(history[0].at, first.at);

    // Past the cap the oldest go, so a long-running session cannot grow
    // this without bound.
    for i in 0..SERVER_LOG_HISTORY {
        record_server_log(&format!("line {i}"));
    }
    let history = server_log_history();
    assert_eq!(history.len(), SERVER_LOG_HISTORY);
    assert_eq!(
        history.last().map(|l| l.message.as_str()),
        Some(format!("line {}", SERVER_LOG_HISTORY - 1).as_str()),
    );
    assert!(
        !history.iter().any(|l| l.message == "connecting"),
        "the first line should have been pushed out by now"
    );

    // Clearing the view clears this too, or the next reload would hand the
    // cleared lines straight back.
    clear_server_log_history();
    assert!(server_log_history().is_empty());
    assert!(
        record_server_log("after clear").seq > second.seq,
        "sequence numbers keep counting across a clear, so a line recorded \
         after one cannot collide with a line the frontend still holds"
    );
    clear_server_log_history();
}

/// Firsthand session contacts sit beside the routing table and are exempt
/// from everything that disciplines a resident: no liveness ping reaches
/// them, so they never accrue a failed query, and the table's staleness
/// purge never sees them. Nothing aged them out at all — a LAN peer that
/// went away stayed in the UI's overlay count, on every search shortlist,
/// in the publish target set, and holding known-peer UDP treatment, until
/// 64 better contacts pushed it out.
#[test]
fn a_session_contact_that_goes_quiet_stops_being_counted() {
    let now = 1_800_000_000i64;
    let contact = |last_seen: i64, last: u8| ember::dht::EmberContact {
        node_id: ember::dht::EmberNodeId([last; 16]),
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, last)), 4672),
        noise_pub: [last; 32],
        ed25519_pub: [last; 32],
        last_seen,
        failed_queries: 0,
    };

    let answering = contact(now - 60, 1);
    let quiet = contact(now - EMBER_CONTACT_STALE_SECS - 1, 2);
    let never_asked = contact(0, 3);

    assert!(ember_session_contact_is_live(&answering, now));
    assert!(
        !ember_session_contact_is_live(&quiet, now),
        "two hours unheard is the same verdict the routing table reaches"
    );
    assert!(
        ember_session_contact_is_live(&never_asked, now),
        "a LAN lead we have not probed yet is not a peer that went silent"
    );

    // And as the sweep applies it.
    let mut map: HashMap<(Ipv4Addr, u16), ember::dht::EmberContact> = HashMap::new();
    for c in [&answering, &quiet, &never_asked] {
        record_ember_session_dht_contact(&mut map, c.clone());
    }
    assert_eq!(map.len(), 3);
    map.retain(|_, c| ember_session_contact_is_live(c, now));
    assert_eq!(map.len(), 2);
    assert!(!map.contains_key(&(Ipv4Addr::new(192, 168, 1, 2), 4672)));

    // The unproven lead is not immortal either: it is the first thing the
    // LRU gives up, which is the order that matters — a proven peer should
    // take its slot, not the clock.
    for i in 0..MAX_EMBER_SESSION_DHT_CONTACTS as u8 {
        record_ember_session_dht_contact(
            &mut map,
            ember::dht::EmberContact {
                node_id: ember::dht::EmberNodeId([0x80 | i; 16]),
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, i, 1)), 4672),
                noise_pub: [0x80 | i; 32],
                ed25519_pub: [0x80 | i; 32],
                last_seen: now - 10,
                failed_queries: 0,
            },
        );
    }
    assert!(map.len() <= MAX_EMBER_SESSION_DHT_CONTACTS);
    assert!(
        !map.contains_key(&(Ipv4Addr::new(192, 168, 1, 3), 4672)),
        "the never-probed lead loses its slot to peers that answer"
    );
}

/// A succession claim hands a room to someone new, so the checks that gate
/// it are the most consequential in the feature. "The owner is silent" and
/// "we have not looked" are the same observation locally, and the claimant
/// picks the timestamp they cite — so neither our snapshot nor their word
/// can be trusted alone.
#[test]
fn a_succession_claim_is_refused_unless_both_we_and_it_show_real_silence() {
    use crate::network::ember::channel::ChannelIdentity;
    use crate::network::ember::dht::publish::SignedRecord;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng as RandOsRng;

    let path = std::env::temp_dir().join(format!(
        "ember-claim-gate-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&path);
    let db = Database::open_at(&path).expect("open db");

    let room = ChannelIdentity::generate();
    let successor = ChannelIdentity::generate();
    let nominee = SigningKey::generate(&mut RandOsRng);
    let nominee_pk = nominee.verifying_key().to_bytes();
    let owner_pk = [0x11u8; 32];
    let channel_id_hex = hex::encode(room.channel_id);

    // A room we are a member of, with a 14-day succession window.
    db.insert_channel(
        &channel_id_hex,
        &hex::encode(room.pubkey),
        "Room",
        "private",
        false,
        None,
        Some(&[0xABu8; 32]),
    )
    .expect("insert channel");
    db.upsert_channel_member(&channel_id_hex, &hex::encode(nominee_pk), "Nominee", 1, None)
        .unwrap();

    let now = chrono::Utc::now().timestamp();
    let day = 86_400i64;
    // Stands in for the drain recording that a moderation search came back
    // *and* that some peer answered it — the drain only writes this when
    // `responded_count() > 0`, so an unanswered search leaves it untouched.
    let confirm_silence_at = |ts: i64| {
        db.touch_channel_moderation_checked(&channel_id_hex, ts).unwrap();
    };
    let claim_blob = |witnessed_ts: i64| -> Vec<u8> {
        let rec = SignedRecord::channel_succession_claim(
            room.channel_id,
            room.pubkey,
            &successor.pubkey,
            witnessed_ts,
            true,
            &nominee,
        );
        let mut blob = rec.data.clone();
        blob.extend_from_slice(&rec.signature);
        blob
    };
    // Our own snapshot of the owner's last word, 30 days stale.
    let stale_owner_ts = now - 30 * day;
    let seed_moderation = |ts: i64| {
        db.apply_channel_moderation(
            &channel_id_hex,
            "Topic",
            "",
            ts,
            &[],
            &[],
            Some(&owner_pk),
            Some(&nominee_pk),
            Some(14),
            None,
            None,
            None,
        )
        .unwrap();
    };
    seed_moderation(stale_owner_ts);

    // Not having looked is not the same as the owner being quiet. A client
    // that just started up with a month-old snapshot must not hand the room
    // over before it has asked whether the owner is still publishing.
    assert_eq!(
        ingest_channel_claim_records(&db, room.channel_id, &[claim_blob(stale_owner_ts)]),
        None,
        "a claim must not be honoured before we have polled at all"
    );
    confirm_silence_at(now - ember::channel::MODERATION_FETCH_SECS * 3 - 60);
    assert_eq!(
        ingest_channel_claim_records(&db, room.channel_id, &[claim_blob(stale_owner_ts)]),
        None,
        "nor on a stale poll"
    );

    // From here on we have confirmed the silence recently.
    confirm_silence_at(now - 10);

    // A claim whose own evidence shows the owner active an hour ago is
    // refused however stale our snapshot is. This was the hole: the window
    // was measured only against our own copy, so a claimant could prove the
    // owner was alive and inherit the room anyway.
    assert_eq!(
        ingest_channel_claim_records(&db, room.channel_id, &[claim_blob(now - 3_600)]),
        None,
        "a claim citing a live owner must be refused"
    );

    // A claimant cannot backdate below what we hold, either.
    assert_eq!(
        ingest_channel_claim_records(&db, room.channel_id, &[claim_blob(stale_owner_ts - day)]),
        None,
        "a claim older than our own record must be refused"
    );

    // Both sides agreeing on real silence, and we have looked: honoured.
    assert_eq!(
        ingest_channel_claim_records(&db, room.channel_id, &[claim_blob(stale_owner_ts)]),
        Some(successor.channel_id),
        "genuine silence, freshly confirmed, is what succession is for"
    );
    assert_eq!(
        db.get_channel(&channel_id_hex).unwrap().unwrap().successor_id,
        hex::encode(successor.channel_id)
    );
}
use crate::network::kad::messages::SearchResultEntry;
use crate::network::kad::types::{
    KadTag, TagName, TagValue, TAG_DESCRIPTION, TAG_FILENAME, TAG_FILERATING,
};

/// Regression: a failed heartbeat clears the "registered" flag and the
/// last-register clock, but not `friend_presence_initial_done`. While the
/// refresh was gated on "registered" that combination matched no retry
/// path at all, so one lost heartbeat dropped the node off the rendezvous
/// server for the rest of the session and friends could no longer find it.
#[test]
fn a_failed_heartbeat_is_retried_rather_than_abandoned() {
    assert!(should_refresh_presence(true, false, None));
}

#[test]
fn presence_is_not_refreshed_before_it_is_established() {
    // The initial-registration path owns this case; refreshing here too
    // would put two registrations in flight at once on every startup.
    assert!(!should_refresh_presence(false, false, None));
    assert!(!should_refresh_presence(
        false,
        false,
        Some(std::time::Duration::from_secs(9_999))
    ));
}

#[test]
fn presence_refresh_waits_for_the_heartbeat_interval() {
    let fresh = std::time::Duration::from_secs(PRESENCE_HEARTBEAT_SECS - 1);
    let due = std::time::Duration::from_secs(PRESENCE_HEARTBEAT_SECS);
    assert!(!should_refresh_presence(true, false, Some(fresh)));
    assert!(should_refresh_presence(true, false, Some(due)));
}

#[test]
fn presence_refresh_never_doubles_up_on_an_attempt_in_flight() {
    assert!(!should_refresh_presence(true, true, None));
    assert!(!should_refresh_presence(
        true,
        true,
        Some(std::time::Duration::from_secs(9_999))
    ));
}

#[test]
fn the_startup_sweep_looks_up_every_friend_rather_than_the_first_few() {
    // The whole point of the queue: the sweep used to stop after three and
    // leave the rest reading offline until the five-minute auto-retry got
    // to them.
    let mut queue: Vec<[u8; 16]> = (0..12u8).map(|i| [i; 16]).collect();
    let mut seen: Vec<[u8; 16]> = Vec::new();
    let mut ticks = 0;
    while !queue.is_empty() {
        seen.extend(drain_initial_friend_search(&mut queue, 5, |_| false));
        ticks += 1;
        assert!(ticks < 10, "the queue has to drain, not cycle");
    }
    assert_eq!(ticks, 3, "12 friends at 5 a tick");
    let expected: Vec<[u8; 16]> = (0..12u8).map(|i| [i; 16]).collect();
    assert_eq!(seen, expected, "every friend, in order, exactly once");
}

#[test]
fn the_startup_sweep_sends_a_full_tick_of_lookups_even_when_most_are_online() {
    // Skipped friends must not spend the budget. Charging them would make a
    // list that is mostly online take a tick per *friend* instead of a tick
    // per five lookups.
    let mut queue: Vec<[u8; 16]> = (0..12u8).map(|i| [i; 16]).collect();
    let online = |fh: &[u8; 16]| fh[0].is_multiple_of(2);
    let first = drain_initial_friend_search(&mut queue, 5, online);
    assert_eq!(
        first,
        vec![[1; 16], [3; 16], [5; 16], [7; 16], [9; 16]],
        "five actual lookups, the evens among them passed over for free"
    );
    // `[10; 16]` is online too, but the budget ran out before it was
    // examined, so it waits for the next tick to be skipped there.
    assert_eq!(
        queue,
        vec![[10; 16], [11; 16]],
        "everything past the budget is kept, untested"
    );
    assert_eq!(
        drain_initial_friend_search(&mut queue, 5, online),
        vec![[11; 16]],
        "the remainder is filtered on its own tick"
    );
    assert!(queue.is_empty());
}

#[test]
fn a_friend_nothing_is_owed_for_leaves_the_startup_sweep_entirely() {
    // Dropped, not deferred: they are already reachable, already being
    // looked up, or no longer a friend. Deferring would re-offer them every
    // tick and the queue would never empty.
    let mut queue = vec![[1; 16], [2; 16]];
    assert!(drain_initial_friend_search(&mut queue, 5, |_| true).is_empty());
    assert!(queue.is_empty(), "a fully skipped tick still drains the queue");
}

#[test]
fn a_failed_heartbeat_backs_off_instead_of_retrying_every_bootstrap_tick() {
    assert_eq!(presence_failure_retry_secs(0), 10);
    assert_eq!(presence_failure_retry_secs(1), 10, "first retry stays fast");
    assert_eq!(presence_failure_retry_secs(2), 20);
    assert_eq!(presence_failure_retry_secs(3), 40);
    assert_eq!(presence_failure_retry_secs(4), 80);
    assert_eq!(presence_failure_retry_secs(5), PRESENCE_HEARTBEAT_SECS);
    assert_eq!(presence_failure_retry_secs(u32::MAX), PRESENCE_HEARTBEAT_SECS);

    let ten = std::time::Duration::from_secs(10);
    let nineteen = std::time::Duration::from_secs(19);
    assert!(
        presence_failure_retry_due(None, None, 1),
        "the first retry after a failure is allowed immediately"
    );
    assert!(presence_failure_retry_due(None, Some(ten), 1));
    assert!(
        !presence_failure_retry_due(None, Some(nineteen), 2),
        "the second failure waits 20s, not another 10s tick"
    );
    assert!(presence_failure_retry_due(
        Some(std::time::Duration::from_secs(PRESENCE_HEARTBEAT_SECS)),
        Some(std::time::Duration::from_secs(1)),
        5
    ));
}

fn outcome(intro_ok: bool, attempted: usize, failed: usize) -> rendezvous::RegistrationOutcome {
    rendezvous::RegistrationOutcome {
        intro_ok,
        sealed_intro_ok: intro_ok,
        pairwise_attempted: attempted,
        pairwise_failed: failed,
        ..Default::default()
    }
}

#[test]
fn intro_failure_does_not_claim_friends_cannot_find_you() {
    // Existing friends still resolve via pairwise; friend-code adds are
    // degraded. The payload must not trip the frontend's no-grace banner
    // (`discoverable: false` + `initial: true`).
    let payload = friend_discoverable_event(&outcome(false, 3, 0), true);
    assert_eq!(payload["discoverable"], serde_json::json!(true));
    assert!(payload.get("initial").is_none());
    assert_eq!(payload["reason"], serde_json::json!("intro_presence_failed"));
    assert_eq!(payload["intro_ok"], serde_json::json!(false));
}

#[test]
fn intro_failure_with_no_friends_is_degraded_not_fatal() {
    let payload = friend_discoverable_event(&outcome(false, 0, 0), true);
    assert_eq!(payload["discoverable"], serde_json::json!(true));
    assert!(payload.get("initial").is_none());
    assert_eq!(payload["reason"], serde_json::json!("intro_presence_failed"));
}

#[test]
fn total_pairwise_and_intro_failure_is_undiscoverable() {
    let payload = friend_discoverable_event(&outcome(false, 4, 4), true);
    assert_eq!(payload["discoverable"], serde_json::json!(false));
    assert_eq!(payload["initial"], serde_json::json!(true));
    assert_eq!(
        payload["reason"],
        serde_json::json!("presence_registration_failed")
    );
    // A later heartbeat with the same blocked outcome must not skip the
    // frontend's 90s grace period (`initial === true` is the tripwire).
    let heartbeat = friend_discoverable_event(&outcome(false, 4, 4), false);
    assert_eq!(heartbeat["discoverable"], serde_json::json!(false));
    assert_eq!(heartbeat["initial"], serde_json::json!(false));
}

#[test]
fn total_pairwise_failure_with_intro_still_discoverable() {
    let payload = friend_discoverable_event(&outcome(true, 4, 4), false);
    assert_eq!(payload["discoverable"], serde_json::json!(true));
    assert!(payload.get("initial").is_none());
    assert_eq!(
        payload["reason"],
        serde_json::json!("pairwise_presence_failed")
    );
}

#[test]
fn partial_pairwise_failure_stays_discoverable() {
    let payload = friend_discoverable_event(&outcome(true, 5, 2), true);
    assert_eq!(payload["discoverable"], serde_json::json!(true));
    assert_eq!(
        payload["reason"],
        serde_json::json!("pairwise_presence_partial")
    );
    assert_eq!(payload["pairwise_attempted"], serde_json::json!(5));
    assert_eq!(payload["pairwise_failed"], serde_json::json!(2));
}

#[test]
fn full_success_has_no_reason() {
    let payload = friend_discoverable_event(&outcome(true, 2, 0), true);
    assert_eq!(payload["discoverable"], serde_json::json!(true));
    assert!(payload.get("reason").is_none());
    assert!(payload.get("initial").is_none());
}

#[test]
fn disconnected_startup_does_not_admit_mapping_probes() {
    assert!(!mapping_probe_allowed_by_activity(
        false, false, false, false
    ));
}

#[test]
fn connected_or_active_work_admits_mapping_probes() {
    assert!(mapping_probe_allowed_by_activity(true, false, false, false));
    assert!(mapping_probe_allowed_by_activity(false, true, false, false));
    assert!(mapping_probe_allowed_by_activity(false, false, true, false));
    assert!(mapping_probe_allowed_by_activity(false, false, false, true));
}

#[test]
fn expected_aich_parser_is_optional_and_strict() {
    assert!(expected_aich_bytes(None).is_none());
    assert_eq!(
        expected_aich_bytes(Some(&"ab".repeat(20))),
        Some([0xabu8; 20])
    );
    assert!(expected_aich_bytes(Some("abcd")).is_none());
    assert!(expected_aich_bytes(Some(&"zz".repeat(20))).is_none());
}

#[tokio::test]
async fn shutdown_fault_wait_never_exceeds_outer_deadline() {
    let started = tokio::time::Instant::now();
    let global = started + std::time::Duration::from_millis(25);
    let phase = shutdown_phase_deadline(global, std::time::Duration::from_secs(30));
    assert!(phase <= global);
    let timed_out =
        tokio::time::timeout_at(phase, tokio::time::sleep(std::time::Duration::from_secs(1)))
            .await;
    assert!(timed_out.is_err());
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "nested fault wait escaped the outer shutdown deadline"
    );
}

#[test]
fn relay_poll_success_preserves_one_second_minimum_cadence() {
    let started = tokio::time::Instant::now();
    assert_eq!(
        relay_ticket_next_round_delay(started, started + std::time::Duration::from_millis(200)),
        std::time::Duration::from_millis(800)
    );
    assert_eq!(
        relay_ticket_next_round_delay(started, started + std::time::Duration::from_secs(2)),
        std::time::Duration::ZERO
    );
}

#[test]
fn advertised_tcp_port_prefers_the_upnp_forward_over_a_stun_remap() {
    // The regression this guards: a gateway can honour a UPnP forward on
    // 4662 while still allocating a fresh external port for the outbound
    // STUN probe. Advertising 51234 sent every connect-back to a port the
    // router was not forwarding, so we self-reported Firewalled even
    // though 4662 was open.
    assert_eq!(
        advertised_tcp_port_from(Some(4662), Some(51234), 4662, false),
        4662
    );
}

#[test]
fn advertised_tcp_port_uses_the_stun_remap_when_upnp_is_not_mapped() {
    // Without a forward of our own, the NAT's observed port is the only
    // reachable one — the CGNAT case STUN keep-alive exists for.
    assert_eq!(
        advertised_tcp_port_from(None, Some(51234), 4662, false),
        51234
    );
}

#[test]
fn advertised_tcp_port_prefers_the_stun_remap_once_the_server_says_lowid() {
    // LowID means the server could not reach what we advertised, so the
    // forward is not working whatever the router reports — double NAT, or
    // CGNAT above a UPnP-capable inner router. Falling back lets the remap
    // reconnect try the one port that has not been ruled out.
    assert_eq!(
        advertised_tcp_port_from(Some(4662), Some(51234), 4662, true),
        51234
    );
    // With no STUN observation there is nothing better to switch to, so the
    // forward stays advertised rather than dropping to a port nobody has
    // suggested is reachable.
    assert_eq!(advertised_tcp_port_from(Some(4662), None, 4662, true), 4662);
}

#[test]
fn login_tcp_port_is_captured_before_session_reset_clears_low_id() {
    let mut low_id = true;
    let port = capture_advertised_tcp_port_then_reset_low_id(
        Some(4662),
        Some(51234),
        4662,
        &mut low_id,
    );
    assert_eq!(port, 51234);
    assert!(!low_id);
}

#[test]
fn advertised_tcp_port_falls_back_to_the_configured_port() {
    assert_eq!(advertised_tcp_port_from(None, None, 4662, false), 4662);
    assert_eq!(advertised_tcp_port_from(None, Some(0), 4662, false), 4662);
    assert_eq!(
        advertised_tcp_port_from(Some(0), Some(51234), 4662, false),
        51234
    );
}

#[test]
fn tcp_port_confirmation_accepts_1to1_immediately() {
    let result = tcp_port_confirmation(4662, None, 0, 4662);
    assert_eq!(result.confirmed_port, Some(4662));
    assert_eq!(result.candidate_port, None);
    assert_eq!(result.stable_hits, 0);
}

#[test]
fn tcp_port_confirmation_ignores_port_zero() {
    let result = tcp_port_confirmation(4662, Some(51234), 1, 0);
    assert_eq!(result.confirmed_port, None);
    assert_eq!(result.candidate_port, Some(51234));
    assert_eq!(result.stable_hits, 1);
}

#[test]
fn tcp_port_confirmation_requires_two_consecutive_hits_for_a_remap() {
    // First observation of a genuine remap becomes a candidate so one
    // transient TCP mapping cannot immediately change advertised state.
    let first = tcp_port_confirmation(4662, None, 0, 51234);
    assert_eq!(first.confirmed_port, None);
    assert_eq!(first.candidate_port, Some(51234));
    assert_eq!(first.stable_hits, 1);

    // Second identical observation confirms it.
    let second = tcp_port_confirmation(4662, first.candidate_port, first.stable_hits, 51234);
    assert_eq!(second.confirmed_port, Some(51234));
    assert_eq!(second.candidate_port, None);
    assert_eq!(second.stable_hits, 0);
}

#[test]
fn should_reconnect_for_tcp_remap_when_lowid_with_a_new_confirmed_port() {
    assert!(should_reconnect_for_tcp_remap(
        true,
        true,
        false,
        Some(51234),
        Some(4662),
        true
    ));
}

#[test]
fn should_not_reconnect_for_tcp_remap_when_already_highid() {
    // Nothing to fix — reconnecting would only risk disrupting a
    // perfectly good HighID session.
    assert!(!should_reconnect_for_tcp_remap(
        false,
        true,
        false,
        Some(51234),
        Some(4662),
        true
    ));
}

#[test]
fn should_not_reconnect_for_tcp_remap_when_disconnected() {
    assert!(!should_reconnect_for_tcp_remap(
        true,
        false,
        false,
        Some(51234),
        Some(4662),
        true
    ));
}

#[test]
fn should_not_reconnect_for_tcp_remap_when_reconnect_already_in_flight() {
    assert!(!should_reconnect_for_tcp_remap(
        true,
        true,
        true,
        Some(51234),
        Some(4662),
        true
    ));
}

#[test]
fn should_not_reconnect_for_tcp_remap_when_port_unconfirmed() {
    assert!(!should_reconnect_for_tcp_remap(
        true,
        true,
        false,
        None,
        Some(4662),
        true
    ));
}

#[test]
fn should_not_reconnect_for_tcp_remap_when_server_already_has_this_port() {
    // The server already knows this exact port (either it was current
    // at login, or a prior reconnect already pushed it) — nothing to
    // gain from reconnecting again.
    assert!(!should_reconnect_for_tcp_remap(
        true,
        true,
        false,
        Some(51234),
        Some(51234),
        true
    ));
}

#[test]
fn should_not_reconnect_for_tcp_remap_during_cooldown() {
    assert!(!should_reconnect_for_tcp_remap(
        true,
        true,
        false,
        Some(51234),
        Some(4662),
        false
    ));
}

#[test]
fn tcp_port_confirmation_resets_candidate_on_flapping_port() {
    let first = tcp_port_confirmation(4662, None, 0, 51234);
    assert_eq!(first.candidate_port, Some(51234));

    // A different port on the next cycle restarts the streak instead of
    // ever being trusted from an inconsistent reading.
    let flapped = tcp_port_confirmation(4662, first.candidate_port, first.stable_hits, 60000);
    assert_eq!(flapped.confirmed_port, None);
    assert_eq!(flapped.candidate_port, Some(60000));
    assert_eq!(flapped.stable_hits, 1);
}

#[test]
fn bootstrap_contact_result_uses_injection_cap() {
    assert_eq!(applied_bootstrap_contact_count(12), 12);
    assert_eq!(
        applied_bootstrap_contact_count(MAX_BOOTSTRAP_CONTACTS + 1),
        MAX_BOOTSTRAP_CONTACTS
    );
}

#[test]
fn bootstrap_contact_result_counts_only_routing_table_accepts() {
    let mut calls = 0;
    let accepted = count_accepted_bootstrap_contacts([1, 2, 3], |_| {
        calls += 1;
        calls != 2
    });
    assert_eq!(accepted, 2);
}

#[test]
fn browse_responses_are_bound_to_the_sending_session() {
    let friend = [0xA1; 16];
    let mut pending = PendingBrowseRequests::new();
    assert_eq!(
        enqueue_browse_request(&mut pending, friend, "first".into(), 11),
        Ok(())
    );
    assert_eq!(
        enqueue_browse_request(&mut pending, friend, "second".into(), 12),
        Ok(())
    );

    // A response from a new/reconnected session cannot consume the old
    // session's queue head.
    assert_eq!(complete_browse_request(&mut pending, friend, 12), None);
    assert_eq!(
        complete_browse_request(&mut pending, friend, 11),
        Some("first".into())
    );
    // The replacement-session request is now the unsent head. The
    // dispatcher must see this transition and send it on session 12.
    let next = pending
        .get(&friend)
        .and_then(|queue| queue.front())
        .unwrap();
    assert_eq!(next.request_id, "second");
    assert_eq!(next.session_id, 12);
    assert!(!next.dispatched);
}

#[tokio::test]
async fn browse_response_uses_origin_stream_during_dual_dial() {
    let (origin_tx, mut origin_rx) = tokio::sync::mpsc::channel(1);
    let (_canonical_tx, mut canonical_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    send_browse_response_to_origin(&origin_tx, vec![1, 2, 3]).unwrap();
    assert_eq!(origin_rx.recv().await, Some(vec![1, 2, 3]));
    assert!(canonical_rx.try_recv().is_err());
}

#[test]
fn cancelling_active_browse_retires_its_session_queue() {
    let friend = [0xB2; 16];
    let mut pending = PendingBrowseRequests::new();
    enqueue_browse_request(&mut pending, friend, "cancelled".into(), 21).unwrap();
    enqueue_browse_request(&mut pending, friend, "queued".into(), 21).unwrap();

    assert_eq!(
        cancel_browse_request(&mut pending, friend, "cancelled"),
        Some((Some(21), vec!["queued".into()]))
    );
    // A late response after cancellation cannot be shown as either the
    // cancelled request or a later browse on the replacement session.
    assert_eq!(complete_browse_request(&mut pending, friend, 21), None);
    enqueue_browse_request(&mut pending, friend, "replacement".into(), 22).unwrap();
    assert_eq!(complete_browse_request(&mut pending, friend, 21), None);
    assert_eq!(
        complete_browse_request(&mut pending, friend, 22),
        Some("replacement".into())
    );
}

/// Removing a friend who still had a live session hung the entire network
/// task. The handler looked the session id up under a read guard and, on
/// this edition, an `if let` scrutinee's temporary outlives the body — so
/// the guard was still held when the retire awaited the write lock on the
/// same map. Nothing recovered from that: no timer fired again, no
/// datagram was served, and shutdown never completed.
///
/// The timeout is the assertion. Without it a regression here hangs the
/// test run instead of failing it.
#[tokio::test]
async fn removing_a_friend_retires_its_session_without_deadlocking() {
    let friend = [0xD4; 16];
    let sessions: upload_server::EmberSessionMap = Arc::new(RwLock::new(HashMap::new()));
    let (tx, _rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    let handle = upload_server::EmberSessionHandle::new(tx, [0u8; 32]);
    let mut shutdown = handle.subscribe_shutdown();
    sessions.write().await.insert(friend, handle);

    let retired = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        retire_current_ember_session(&sessions, friend),
    )
    .await
    .expect("retiring a live session must not deadlock");

    assert!(retired);
    shutdown
        .changed()
        .await
        .expect("the retired session is told to close");
    assert!(*shutdown.borrow());
    assert!(!sessions.read().await.contains_key(&friend));

    // A friend with no session is a no-op, not a hang or a panic.
    assert!(
        !tokio::time::timeout(
            std::time::Duration::from_secs(5),
            retire_current_ember_session(&sessions, friend),
        )
        .await
        .expect("a second removal must not deadlock either")
    );
}

#[tokio::test]
async fn cancelling_browse_retires_the_live_session_before_rebrowse() {
    let friend = [0xC3; 16];
    let sessions: upload_server::EmberSessionMap = Arc::new(RwLock::new(HashMap::new()));
    let (first_tx, _first_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    let first = upload_server::EmberSessionHandle::new(first_tx, [0u8; 32]);
    let first_id = first.session_id();
    let mut first_shutdown = first.subscribe_shutdown();
    sessions.write().await.insert(friend, first);

    let mut pending = PendingBrowseRequests::new();
    enqueue_browse_request(&mut pending, friend, "first".into(), first_id).unwrap();
    let (retired, _) = cancel_browse_request(&mut pending, friend, "first").unwrap();
    assert_eq!(retired, Some(first_id));
    assert!(retire_ember_session(&sessions, friend, first_id).await);
    first_shutdown
        .changed()
        .await
        .expect("retired session sends shutdown");
    assert!(*first_shutdown.borrow());
    assert!(!sessions.read().await.contains_key(&friend));

    // A re-browse receives a distinct session, and an accidental repeat
    // cancellation cannot close the retired session a second time.
    assert!(!retire_ember_session(&sessions, friend, first_id).await);
    let (second_tx, _second_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    let second = upload_server::EmberSessionHandle::new(second_tx, [0u8; 32]);
    let second_id = second.session_id();
    sessions.write().await.insert(friend, second);
    assert_ne!(first_id, second_id);
    assert!(retire_ember_session(&sessions, friend, second_id).await);
}

#[tokio::test]
async fn reconciliation_drains_fresh_part_hashes_even_when_unused() {
    let hash = [0xA5; 16];
    let fresh = Arc::new(RwLock::new(HashMap::from([(hash, vec![[0x5A; 16]])])));

    assert_eq!(
        take_fresh_part_hashes(&fresh, &hash).await,
        Some(vec![[0x5A; 16]])
    );
    assert!(fresh.read().await.is_empty());
}

fn sample_download_source() -> DownloadSource {
    DownloadSource {
        peer_ip: "127.0.0.1".to_string(),
        peer_port: 4662,
        available_parts: Vec::new(),
        peer_user_hash: None,
        peer_connect_options: None,
    }
}

fn sample_search_result(hash: &str) -> SearchResult {
    SearchResult {
        file: FileInfo {
            id: hash.to_string(),
            name: "file.bin".to_string(),
            path: String::new(),
            size: 1234,
            hash: hash.to_string(),
            aich_hash: String::new(),
            ember_file_hash: String::new(),
            extension: "bin".to_string(),
            modified_at: 0,
            priority: "normal".to_string(),
            requests: 0,
            accepted: 0,
            bytes_transferred: 0,
            alltime_requests: 0,
            alltime_accepted: 0,
            alltime_transferred: 0,
            complete_sources: 0,
            folder: String::new(),
            shared: false,
            friends_only: false,
            shared_kad: false,
            shared_ed2k: false,
            shared_ember: false,
        },
        peer_id: String::new(),
        peer_name: String::new(),
        availability: 1,
        file_type: String::new(),
        source_addresses: Vec::new(),
        rating: None,
        comment: None,
        media: None,
        spam_rating: 0,
        is_spam: false,
        clean_name: String::new(),
        result_origin: "KAD".to_string(),
        origin_server_ip: None,
        spam_reasons: Vec::new(),
        spam_reason_details: Vec::new(),
    }
}

fn sample_active_search_request(request_id: u64) -> ActiveSearchRequest {
    ActiveSearchRequest {
        request_id,
        server_pending: false,
        kad_pending: true,
        udp_pending: false,
        ember_pending: false,
        kad_ran: true,
        ember_ran: false,
        udp_search_deadline: 0,
        udp_search_sent_ips: HashSet::new(),
        ed2k_found_sources: 0,
        udp_found_sources: 0,
        ed2k_noted_availability: HashMap::new(),
        ed2k_noted_complete_sources: HashMap::new(),
        dht_noted_availability: HashMap::new(),
        file_type_filter: None,
        min_size: None,
        max_size: None,
        file_extension: None,
        min_availability: None,
        keywords: Vec::new(),
        server_ip: None,
        server_result_count: 0,
        streamed_hashes: std::collections::HashSet::new(),
        exclude_hashes: std::collections::HashSet::new(),
        batch_spam: crate::search::spam::BatchSpamContext::default(),
    }
}

#[test]
fn udp_search_leg_completes_once_grace_period_expires() {
    // Age already past the grace threshold, deadline still far away:
    // ordinary quiet-period completion, not the hard deadline.
    assert!(udp_search_leg_should_complete(31, 30, 1_000, 1_000_000));
    assert!(!udp_search_leg_should_complete(30, 30, 1_000, 1_000_000));
}

#[test]
fn udp_search_leg_completes_at_hard_deadline_despite_fresh_results() {
    // Age keeps getting reset to 0 (as it would by a trickle of real or
    // spoofed SearchResult batches), so the grace timer alone would
    // never fire — but `now` has reached the absolute deadline set when
    // the leg was queued, so the leg must still complete.
    assert!(udp_search_leg_should_complete(0, 30, 5_000, 5_000));
    assert!(udp_search_leg_should_complete(0, 30, 5_001, 5_000));
    assert!(!udp_search_leg_should_complete(0, 30, 4_999, 5_000));
}

#[test]
fn udp_search_leg_stays_open_when_neither_condition_met() {
    assert!(!udp_search_leg_should_complete(5, 30, 1_000, 2_000));
}

/// Regression guard for the KAD/server streaming cross-batch dedup fix:
/// a hash already forwarded to the UI in an earlier streamed batch for
/// this search must be dropped from a later batch, while a genuinely
/// new hash still passes through. Without this, the same file
/// re-announced by a different KAD node / eD2K server got re-scored by
/// the batch-local spam heuristics a second time, which could flip
/// `is_spam` after the row was already shown — see
/// `ActiveSearchRequest::streamed_hashes`.
#[test]
fn dedup_streamed_batch_drops_hash_already_streamed_this_request() {
    let mut active = Some(sample_active_search_request(42));

    let mut batch1 = vec![sample_search_result("aaaa"), sample_search_result("bbbb")];
    let resights1 = dedup_streamed_batch(&mut active, 42, &mut batch1);
    assert_eq!(batch1.len(), 2);
    assert!(resights1.is_empty());
    // Hashes are marked only after a successful emit.
    mark_streamed_hashes(active.as_mut().unwrap(), &batch1);

    let mut batch2 = vec![sample_search_result("aaaa"), sample_search_result("cccc")];
    let resights2 = dedup_streamed_batch(&mut active, 42, &mut batch2);
    assert_eq!(
        batch2
            .iter()
            .map(|r| r.file.hash.as_str())
            .collect::<Vec<_>>(),
        vec!["cccc"],
    );
    assert_eq!(resights2.len(), 1);
    assert_eq!(resights2[0].file.hash, "aaaa");
}

/// A related search seeds `exclude_hashes` with the file it was started
/// from. Those must be dropped outright — not returned as ed2k
/// availability re-sights, which would have the UI try to update a row it
/// never showed.
#[test]
fn dedup_streamed_batch_drops_excluded_hashes_entirely() {
    let mut active = sample_active_search_request(42);
    active.exclude_hashes.insert("seedhash".to_string());
    let mut active = Some(active);

    let mut batch = vec![
        SearchResult {
            result_origin: crate::search::merge::ORIGIN_SERVER_TCP.to_string(),
            availability: 9,
            ..sample_search_result("seedhash")
        },
        sample_search_result("otherhash"),
    ];
    let resights = dedup_streamed_batch(&mut active, 42, &mut batch);
    assert_eq!(
        batch
            .iter()
            .map(|r| r.file.hash.as_str())
            .collect::<Vec<_>>(),
        vec!["otherhash"],
    );
    assert!(
        resights.is_empty(),
        "an excluded hash must not come back as an availability update"
    );
}

#[test]
fn related_search_capability_reads_the_emule_tcp_flag() {
    assert!(related_search_flag_set(
        ed2k::server::SRV_TCPFLG_RELATEDSEARCH
    ));
    assert!(related_search_flag_set(
        ed2k::server::SRV_TCPFLG_RELATEDSEARCH | ed2k::server::SRV_TCPFLG_COMPRESSION
    ));
    assert!(!related_search_flag_set(0));
    assert!(!related_search_flag_set(
        ed2k::server::SRV_TCPFLG_COMPRESSION | ed2k::server::SRV_TCPFLG_UNICODE
    ));
}

#[test]
fn dedup_streamed_batch_returns_ed2k_resights_without_keeping_in_batch() {
    let mut active = Some(sample_active_search_request(42));
    let mut first = vec![SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_TCP.to_string(),
        availability: 10,
        ..sample_search_result("deadbeef")
    }];
    assert!(dedup_streamed_batch(&mut active, 42, &mut first).is_empty());
    mark_streamed_hashes(active.as_mut().unwrap(), &first);

    let mut second = vec![SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_UDP.to_string(),
        availability: 7,
        ..sample_search_result("deadbeef")
    }];
    let resights = dedup_streamed_batch(&mut active, 42, &mut second);
    assert!(second.is_empty());
    assert_eq!(resights.len(), 1);
    assert_eq!(resights[0].availability, 7);
}

/// The connected server answers in one ~200-row batch on a 2 s timer; the
/// UDP sweep leaves at one packet per 750 ms. Sharing a single 100-source
/// budget between them meant that first TCP reply spent the whole thing
/// before three of the other servers had been asked, and the sweep's queue
/// was then cleared — a "Global" search that reached two or three of a
/// hundred servers. What the connected server indexes says nothing about
/// what the rest do, which is the entire reason the global leg exists.
#[test]
fn a_tcp_batch_cannot_spend_the_udp_sweeps_budget() {
    let mut active = sample_active_search_request(1);
    let none = HashSet::new();

    // A generous first batch from the connected server: far more sources
    // than the old shared cap of 100 allowed.
    let tcp: Vec<SearchResult> = (0..300)
        .map(|i| SearchResult {
            result_origin: crate::search::merge::ORIGIN_SERVER_TCP.to_string(),
            availability: 5,
            ..sample_search_result(&format!("tcp{i}"))
        })
        .collect();
    assert!(
        !note_ed2k_search_results(&mut active, &tcp, &none),
        "the connected server's own reply must never stop the UDP sweep"
    );
    assert_eq!(active.ed2k_found_sources, 1_500);
    assert_eq!(
        active.udp_found_sources, 0,
        "nothing the TCP leg found belongs to the sweep's budget"
    );

    // The sweep's own replies do advance it, and it does still have a
    // backstop.
    let udp: Vec<SearchResult> = (0..MAX_UDP_SEARCH_SOURCES / ED2K_SEARCH_SOURCE_CAP)
        .map(|i| SearchResult {
            result_origin: crate::search::merge::ORIGIN_SERVER_UDP.to_string(),
            availability: ED2K_SEARCH_SOURCE_CAP,
            ..sample_search_result(&format!("udp{i}"))
        })
        .collect();
    assert!(
        !note_ed2k_search_results(&mut active, &udp, &none),
        "exactly at the backstop is still under it"
    );
    assert_eq!(active.udp_found_sources, MAX_UDP_SEARCH_SOURCES);

    let one_more = SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_UDP.to_string(),
        availability: 1,
        ..sample_search_result("udp-last")
    };
    assert!(
        note_ed2k_search_results(&mut active, &[one_more], &none),
        "past the backstop the sweep stops"
    );
}

/// The backstop has to sit above the point where a server signals it has
/// more to give, or the "More results" gate — which requires a full 200-row
/// batch *and* room under the budget — can never open. Those were the two
/// halves of one `if`, and `note_ed2k_search_results` charges the batch
/// before the gate reads the counter, so page two was never asked for.
#[test]
fn the_more_results_gate_is_reachable() {
    // The batch size that makes a server worth asking again.
    const FULL_BATCH: u32 = 200;
    assert!(
        MAX_SERVER_MORE_REQUESTS >= 1,
        "at least one follow-up page, or the loop is decorative"
    );
    assert!(
        MAX_UDP_SEARCH_SOURCES >= FULL_BATCH * ED2K_SEARCH_SOURCE_CAP,
        "the sweep's backstop has to outlast a whole well-sourced batch, or \
         it stops being a backstop and starts being the limit"
    );

    // The gate no longer consults a source budget at all, so its two halves
    // can no longer contradict each other: a batch large enough to ask about
    // leaves the sweep's counter untouched.
    let mut active = sample_active_search_request(1);
    let none = HashSet::new();
    let batch: Vec<SearchResult> = (0..FULL_BATCH)
        .map(|i| SearchResult {
            result_origin: crate::search::merge::ORIGIN_SERVER_TCP.to_string(),
            availability: ED2K_SEARCH_SOURCE_CAP,
            ..sample_search_result(&format!("row{i}"))
        })
        .collect();
    note_ed2k_search_results(&mut active, &batch, &none);
    assert_eq!(
        active.ed2k_found_sources,
        FULL_BATCH * ED2K_SEARCH_SOURCE_CAP
    );
    assert_eq!(
        active.udp_found_sources, 0,
        "the server's own pages must not spend the sweep's budget"
    );
}

#[test]
fn note_ed2k_search_results_udp_sums_tcp_uses_max() {
    let mut active = sample_active_search_request(1);
    let none = HashSet::new();
    let a = SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_TCP.to_string(),
        availability: 2,
        ..sample_search_result("hash1")
    };
    assert!(!note_ed2k_search_results(&mut active, &[a], &none));
    assert_eq!(active.ed2k_found_sources, 2);

    // TCP More re-list: max, not sum.
    let more = SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_TCP.to_string(),
        availability: 3,
        ..sample_search_result("hash1")
    };
    assert!(!note_ed2k_search_results(&mut active, &[more], &none));
    assert_eq!(active.ed2k_noted_availability.get("hash1"), Some(&3));
    assert_eq!(active.ed2k_found_sources, 3);

    // UDP cross-server: sum onto noted total.
    let udp = SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_UDP.to_string(),
        availability: 4,
        ..sample_search_result("hash1")
    };
    assert!(!note_ed2k_search_results(&mut active, &[udp], &none));
    assert_eq!(active.ed2k_noted_availability.get("hash1"), Some(&7));
    assert_eq!(active.ed2k_found_sources, 5); // spam-capped at 5
}

/// The per-hash ed2k totals are bounded like every other per-hash map a
/// search keeps. They were the only ones that were not, so a global sweep
/// of every server in the list could grow them for as long as it ran.
/// Past the cap a file already being tracked must still accumulate — the
/// rows on screen are the ones that need their running total.
#[test]
fn ed2k_noted_totals_stop_growing_at_the_soft_cap() {
    let mut active = sample_active_search_request(1);
    let none = HashSet::new();
    let batch: Vec<SearchResult> = (0..MAX_STREAMED_HASHES_SOFT_CAP)
        .map(|i| SearchResult {
            result_origin: crate::search::merge::ORIGIN_SERVER_UDP.to_string(),
            availability: 1,
            ..sample_search_result(&format!("hash{i}"))
        })
        .collect();
    note_ed2k_search_results(&mut active, &batch, &none);
    assert_eq!(
        active.ed2k_noted_availability.len(),
        MAX_STREAMED_HASHES_SOFT_CAP
    );

    let fresh = SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_UDP.to_string(),
        availability: 4,
        ..sample_search_result("past-the-cap")
    };
    note_ed2k_search_results(&mut active, &[fresh], &none);
    assert_eq!(
        active.ed2k_noted_availability.len(),
        MAX_STREAMED_HASHES_SOFT_CAP,
        "a hash first seen past the cap must not grow the map"
    );
    assert!(active.ed2k_noted_complete_sources.len() <= MAX_STREAMED_HASHES_SOFT_CAP);

    let resight = SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_UDP.to_string(),
        availability: 5,
        ..sample_search_result("hash0")
    };
    note_ed2k_search_results(&mut active, &[resight], &none);
    assert_eq!(
        active.ed2k_noted_availability.get("hash0"),
        Some(&6),
        "an already-tracked hash must keep summing past the cap"
    );

    // An untracked hash has no stored previous value, so counting it would
    // add its whole slice on every sighting rather than a delta — which ends
    // a global sweep early against `MAX_UDP_SEARCH_SOURCES`.
    let before = active.udp_found_sources;
    for _ in 0..5 {
        let repeat = SearchResult {
            result_origin: crate::search::merge::ORIGIN_SERVER_UDP.to_string(),
            availability: 4,
            ..sample_search_result("past-the-cap")
        };
        note_ed2k_search_results(&mut active, &[repeat], &none);
    }
    assert_eq!(
        active.udp_found_sources, before,
        "a hash the cap refused to track must not advance the stop counter"
    );
}

/// eMule `AddResultCount`: shared/downloading hashes update the noted
/// availability map (UI) but must not advance `ed2k_found_sources`.
#[test]
fn note_ed2k_search_results_skips_owned_hashes_for_cap() {
    let mut active = sample_active_search_request(1);
    let skip: HashSet<String> = ["ownedhash".to_string()].into_iter().collect();
    let owned = SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_TCP.to_string(),
        availability: 4,
        ..sample_search_result("ownedhash")
    };
    assert!(!note_ed2k_search_results(&mut active, &[owned], &skip));
    assert_eq!(active.ed2k_found_sources, 0);
    assert_eq!(active.ed2k_noted_availability.get("ownedhash"), Some(&4));

    let other = SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_TCP.to_string(),
        availability: 2,
        ..sample_search_result("otherhash")
    };
    assert!(!note_ed2k_search_results(&mut active, &[other], &skip));
    assert_eq!(active.ed2k_found_sources, 2);
}

/// A re-sight carries one server's slice; the row carries the file's total.
/// The absolute total is what the row must be emitted with, since the UI
/// merges by max and would otherwise keep whichever single server answered
/// with the most.
#[test]
fn a_resight_is_emitted_with_every_servers_sources_summed() {
    let mut active = sample_active_search_request(1);
    let none = HashSet::new();
    let first = SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_TCP.to_string(),
        availability: 25,
        ..sample_search_result("hash1")
    };
    note_ed2k_search_results(&mut active, &[first], &none);

    let mut resights = vec![SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_UDP.to_string(),
        availability: 4,
        ..sample_search_result("hash1")
    }];
    note_ed2k_resight_availability(&mut active, &mut resights, &none);
    assert_eq!(resights[0].availability, 29);
}

/// Complete sources accumulate across servers exactly as availability does,
/// because eMule's `AddCompleteSources` is `AddSources` with a different
/// tag. This lives here rather than only in `search::merge` because a
/// streamed re-sight carries one server's slice: the frontend merges
/// batches by max, so a row emitted with anything but the absolute total
/// would settle on whichever single server answered with the most.
#[test]
fn a_resight_is_emitted_with_every_servers_complete_sources_summed() {
    let mut active = sample_active_search_request(1);
    let none = HashSet::new();
    let ed2k_row = |origin: &str, avail: u32, complete: u32| {
        let mut r = SearchResult {
            result_origin: origin.to_string(),
            availability: avail,
            ..sample_search_result("hash1")
        };
        r.file.complete_sources = complete;
        r
    };

    note_ed2k_search_results(
        &mut active,
        &[ed2k_row(crate::search::merge::ORIGIN_SERVER_TCP, 25, 3)],
        &none,
    );
    assert_eq!(
        active.ed2k_noted_complete_sources.get("hash1"),
        Some(&3),
        "the first server's count stands on its own"
    );

    // A TCP "More results" re-list repeats the same server's figure, so it
    // replaces rather than accumulates.
    note_ed2k_search_results(
        &mut active,
        &[ed2k_row(crate::search::merge::ORIGIN_SERVER_TCP, 25, 4)],
        &none,
    );
    assert_eq!(active.ed2k_noted_complete_sources.get("hash1"), Some(&4));

    // A UDP reply is a different server, so it adds.
    let mut resights = vec![ed2k_row(crate::search::merge::ORIGIN_SERVER_UDP, 4, 5)];
    note_ed2k_resight_availability(&mut active, &mut resights, &none);
    assert_eq!(resights[0].availability, 29);
    assert_eq!(resights[0].file.complete_sources, 9);
    assert!(
        resights[0].file.complete_sources <= resights[0].availability,
        "summing both keeps the pair readable as a ratio"
    );
}

/// The client-side "Min sources" filter drops rows, and a re-sight is not a
/// row — it is an increment to one already on screen. Filtering the
/// increment took a second server's sources off a file that plainly met the
/// minimum, so the ordering here is the fix: sum first, and let the filter
/// judge the total.
#[test]
fn min_sources_does_not_eat_the_sources_a_second_server_adds() {
    let mut active = sample_active_search_request(1);
    active.min_availability = Some(10);
    let none = HashSet::new();
    let first = SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_TCP.to_string(),
        availability: 25,
        ..sample_search_result("hash1")
    };
    note_ed2k_search_results(&mut active, &[first], &none);

    let mut resights = vec![SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_UDP.to_string(),
        availability: 4,
        ..sample_search_result("hash1")
    }];
    note_ed2k_resight_availability(&mut active, &mut resights, &none);
    assert_eq!(active.ed2k_noted_availability.get("hash1"), Some(&29));
    let kept = filter_results_by_client_constraints(resights, &active);
    assert_eq!(
        kept.len(),
        1,
        "a 4-source update to a 29-source row must survive a minimum of 10"
    );
    assert_eq!(kept[0].availability, 29);
}

/// Kad and Ember re-sights are left out of the ed2k total: folding them in
/// would count one swarm twice. They have a running total of their own.
#[test]
fn a_dht_resight_is_left_out_of_the_ed2k_total() {
    let mut active = sample_active_search_request(1);
    let none = HashSet::new();
    let mut resights = vec![
        SearchResult {
            result_origin: crate::search::merge::ORIGIN_KAD.to_string(),
            availability: 6,
            ..sample_search_result("hash1")
        },
        SearchResult {
            result_origin: crate::search::merge::ORIGIN_EMBER.to_string(),
            availability: 2,
            ..sample_search_result("hash1")
        },
    ];
    note_ed2k_resight_availability(&mut active, &mut resights, &none);
    assert_eq!(resights[0].availability, 6);
    assert_eq!(resights[1].availability, 2);
    assert!(active.ed2k_noted_availability.is_empty());
    assert_eq!(active.ed2k_found_sources, 0);
}

fn kad_row(hash: &str, availability: u32) -> SearchResult {
    SearchResult {
        result_origin: crate::search::merge::ORIGIN_KAD.to_string(),
        availability,
        ..sample_search_result(hash)
    }
}

/// Both DHT legs hand over only the records they have not converted before,
/// so the count on a row is that slice's. The row has to carry what the
/// slices add up to, or the UI's max-merge keeps the biggest single slice.
#[test]
fn kad_slices_add_up_to_a_running_total_as_they_arrive() {
    let mut active = sample_active_search_request(1);
    let mut first = vec![kad_row("hash1", 3)];
    note_dht_availability(&mut active, &mut first, DhtBatchKind::Incremental);
    assert_eq!(first[0].availability, 3);

    let mut second = vec![kad_row("hash1", 5)];
    note_dht_availability(&mut active, &mut second, DhtBatchKind::Incremental);
    assert_eq!(
        second[0].availability, 8,
        "a file eight KAD nodes published must not read as five"
    );

    let mut third = vec![kad_row("hash1", 2)];
    note_dht_availability(&mut active, &mut third, DhtBatchKind::Incremental);
    assert_eq!(third[0].availability, 10);
}

/// The closing batch of either leg is a rebuild over every record gathered,
/// which is the same total the slices already added up to. Folding it in as
/// an increment would double every count as the search finished.
#[test]
fn the_closing_rebuild_replaces_the_total_rather_than_doubling_it() {
    let mut active = sample_active_search_request(1);
    for slice in [3, 5, 2] {
        let mut batch = vec![kad_row("hash1", slice)];
        note_dht_availability(&mut active, &mut batch, DhtBatchKind::Incremental);
    }

    let mut closing = vec![kad_row("hash1", 10)];
    note_dht_availability(&mut active, &mut closing, DhtBatchKind::Cumulative);
    assert_eq!(closing[0].availability, 10);
}

/// A rebuild that comes back larger than the slices did (an entry the
/// streaming cursor passed over, say) is still authoritative.
#[test]
fn a_larger_rebuild_wins_over_what_the_slices_added_up_to() {
    let mut active = sample_active_search_request(1);
    let mut first = vec![kad_row("hash1", 4)];
    note_dht_availability(&mut active, &mut first, DhtBatchKind::Incremental);

    let mut closing = vec![kad_row("hash1", 9)];
    note_dht_availability(&mut active, &mut closing, DhtBatchKind::Cumulative);
    assert_eq!(closing[0].availability, 9);
}

/// Across legs the biggest count wins rather than the sum: a file on both
/// KAD and Ember is one swarm seen twice. Keeping a total per leg is what
/// stops the UI's max-merge from quietly adding them.
#[test]
fn one_file_on_two_dht_legs_keeps_a_total_per_leg() {
    let mut active = sample_active_search_request(1);
    let mut kad = vec![kad_row("hash1", 6)];
    note_dht_availability(&mut active, &mut kad, DhtBatchKind::Incremental);
    assert_eq!(kad[0].availability, 6);

    let mut ember = vec![SearchResult {
        result_origin: crate::search::merge::ORIGIN_EMBER.to_string(),
        availability: 2,
        ..sample_search_result("hash1")
    }];
    note_dht_availability(&mut active, &mut ember, DhtBatchKind::Incremental);
    assert_eq!(
        ember[0].availability, 2,
        "Ember's two publishers must not inherit KAD's six nodes"
    );

    let noted = active.dht_noted_availability.get("hash1").copied().unwrap();
    assert_eq!((noted.kad, noted.ember), (6, 2));
}

/// Server rows are the ed2k total's business; this pass must not touch them
/// or a file found on both a server and KAD would have the two added.
#[test]
fn a_server_row_is_left_to_the_ed2k_total() {
    let mut active = sample_active_search_request(1);
    let mut rows = vec![SearchResult {
        result_origin: crate::search::merge::ORIGIN_SERVER_TCP.to_string(),
        availability: 25,
        ..sample_search_result("hash1")
    }];
    note_dht_availability(&mut active, &mut rows, DhtBatchKind::Incremental);
    assert_eq!(rows[0].availability, 25);
    assert!(active
        .dht_noted_availability
        .get("hash1")
        .is_none_or(|n| n.kad == 0 && n.ember == 0));
}

/// Publisher counts are unverifiable claims arriving one node at a time, so
/// the running total is held to the same ceiling the per-batch tags are.
#[test]
fn the_running_total_is_capped_like_the_per_batch_counts() {
    let mut active = sample_active_search_request(1);
    for _ in 0..3 {
        let mut batch = vec![kad_row("hash1", MAX_KAD_AVAILABILITY)];
        note_dht_availability(&mut active, &mut batch, DhtBatchKind::Incremental);
        assert_eq!(batch[0].availability, MAX_KAD_AVAILABILITY);
    }
    assert_eq!(
        active.dht_noted_availability.get("hash1").unwrap().kad,
        MAX_KAD_AVAILABILITY
    );
}

/// A batch with no matching active search (already replaced by a newer
/// one, or none running) must pass through unfiltered rather than
/// silently dropping results or filtering against the wrong search's
/// dedup set.
#[test]
fn dedup_streamed_batch_is_noop_for_mismatched_or_missing_request() {
    let mut none_active: Option<ActiveSearchRequest> = None;
    let mut batch = vec![sample_search_result("aaaa")];
    assert!(dedup_streamed_batch(&mut none_active, 1, &mut batch).is_empty());
    assert_eq!(
        batch.len(),
        1,
        "no active search at all must not filter anything"
    );

    let mut active = Some(sample_active_search_request(1));
    let mut batch = vec![sample_search_result("aaaa")];
    assert!(dedup_streamed_batch(&mut active, 999, &mut batch).is_empty());
    assert_eq!(
        batch.len(),
        1,
        "batch for a different (stale/replaced) request id must pass through unfiltered"
    );
}

/// Regression guard: hitting `MAX_STREAMED_HASHES_SOFT_CAP` must not
/// disable dedup entirely. Hashes tracked before the cap was reached
/// should keep being filtered on every later sighting; only a brand
/// new hash first seen after the cap goes untracked (accepted
/// trade-off — see the constant's doc comment).
#[test]
fn dedup_streamed_batch_keeps_deduping_already_tracked_hashes_past_soft_cap() {
    let mut active = sample_active_search_request(7);
    for i in 0..MAX_STREAMED_HASHES_SOFT_CAP {
        active.streamed_hashes.insert(format!("preexisting-{i}"));
    }
    let mut active = Some(active);

    let mut batch = vec![
        sample_search_result("preexisting-0"),
        sample_search_result("brand-new"),
    ];
    let resights = dedup_streamed_batch(&mut active, 7, &mut batch);
    assert_eq!(
        batch
            .iter()
            .map(|r| r.file.hash.as_str())
            .collect::<Vec<_>>(),
        vec!["brand-new"],
        "already-tracked hash must still be dropped even past the soft cap, \
         and a genuinely new hash must still pass through"
    );
    assert_eq!(resights.len(), 1);
    let active_ref = active.as_ref().unwrap();
    assert_eq!(
        active_ref.streamed_hashes.len(),
        MAX_STREAMED_HASHES_SOFT_CAP,
        "set must not grow past the soft cap"
    );
    assert!(
        !active_ref.streamed_hashes.contains("brand-new"),
        "new hashes seen past the cap are not tracked (documented trade-off)"
    );
}

/// Regression guard for the KAD bootstrap-hammering fix: the interval
/// must start at the same 10s cadence as before (no behavior change for
/// a healthy, quickly-connecting client), strictly grow with `shift`,
/// and cap at 10 minutes instead of growing unbounded.
#[test]
fn hardcoded_bootstrap_backoff_interval_grows_then_caps() {
    assert_eq!(hardcoded_bootstrap_backoff_interval(0), 10);
    assert_eq!(hardcoded_bootstrap_backoff_interval(1), 20);
    assert_eq!(hardcoded_bootstrap_backoff_interval(2), 40);
    assert_eq!(hardcoded_bootstrap_backoff_interval(3), 80);
    assert_eq!(hardcoded_bootstrap_backoff_interval(4), 160);
    assert_eq!(hardcoded_bootstrap_backoff_interval(5), 320);
    assert_eq!(hardcoded_bootstrap_backoff_interval(6), 600);
    // Must stay capped at 10 minutes for any larger shift, including
    // values well past what `1i64 << shift` could otherwise overflow to.
    assert_eq!(hardcoded_bootstrap_backoff_interval(7), 600);
    assert_eq!(hardcoded_bootstrap_backoff_interval(100), 600);
    assert_eq!(hardcoded_bootstrap_backoff_interval(u32::MAX), 600);
}

#[test]
fn source_injection_reports_full_channel() {
    let (tx, _rx) = mpsc::channel(1);
    tx.try_send(sample_download_source()).unwrap();

    assert_eq!(
        try_inject_source(Some(&tx), &sample_download_source()),
        SourceInjectionResult::Full,
    );
}

#[test]
fn source_injection_reports_closed_channel() {
    let (tx, rx) = mpsc::channel(1);
    drop(rx);

    assert_eq!(
        try_inject_source(Some(&tx), &sample_download_source()),
        SourceInjectionResult::Closed,
    );
}

/// Build a `FOUND_VALUE`-shaped keyword blob (`record_data || signature`)
/// signed by `sk`, matching what `build_ember_keyword_built` parses.
fn ember_kw_blob(
    sk: &ed25519_dalek::SigningKey,
    keyword: &str,
    file_hash: [u8; 16],
    size: u64,
    name: &str,
) -> Vec<u8> {
    ember_kw_blob_with_digest(sk, keyword, file_hash, [0u8; 32], size, name)
}

/// The same, carrying a content digest, for the corroboration rules.
fn ember_kw_blob_with_digest(
    sk: &ed25519_dalek::SigningKey,
    keyword: &str,
    file_hash: [u8; 16],
    ember_file_hash: [u8; 32],
    size: u64,
    name: &str,
) -> Vec<u8> {
    let rec = ember::dht::publish::SignedRecord::keyword(
        keyword,
        file_hash,
        ember_file_hash,
        size,
        name,
        sk,
    );
    let mut blob = rec.data.clone();
    blob.extend_from_slice(&rec.signature);
    blob
}

/// The same for a source blob, as `parse_ember_source_records` parses it.
/// `last_octet` only has to keep the advertised contacts distinct.
fn ember_source_blob(
    sk: &ed25519_dalek::SigningKey,
    file_hash: [u8; 16],
    ember_file_hash: [u8; 32],
    last_octet: u8,
) -> Vec<u8> {
    ember_source_blob_contact(
        sk,
        file_hash,
        ember_file_hash,
        ember::dht::publish::SourceContact {
            ip: Ipv4Addr::new(1, 2, 3, last_octet),
            tcp_port: 4662,
            udp_port: 4672,
            flags: 0,
            noise_pub: [0u8; 32],
            ..Default::default()
        },
    )
}

fn ember_source_blob_contact(
    sk: &ed25519_dalek::SigningKey,
    file_hash: [u8; 16],
    ember_file_hash: [u8; 32],
    contact: ember::dht::publish::SourceContact,
) -> Vec<u8> {
    let rec = ember::dht::publish::SignedRecord::source(
        file_hash,
        ember_file_hash,
        1,
        "shared.iso",
        contact,
        sk,
    );
    let mut blob = rec.data.clone();
    blob.extend_from_slice(&rec.signature);
    blob
}

fn record_ref(file: u8, key: u8) -> EmberRecordRef {
    EmberRecordRef {
        file_hash: [file; 16],
        kind: EmberPublishKind::Keyword,
        key: [key; 16],
    }
}

/// The schedule must only advance for records a peer actually confirmed,
/// or a publish that reached nobody locks the file out for the full
/// republish interval.
#[test]
fn only_acked_records_advance_the_republish_schedule() {
    let mut pub_ = EmberBatchPublisher::default();
    let node = ember::dht::EmberNodeId([7u8; 16]);
    let other = ember::dht::EmberNodeId([8u8; 16]);
    let a = record_ref(0xAB, 1);

    pub_.in_flight.insert(
        1,
        EmberBatchInFlight {
            node_id: node,
            records: vec![a],
            deadline: std::time::Instant::now() + EMBER_BATCH_ACK_TIMEOUT,
        },
    );

    // An ack from a node we did not send to proves nothing and must not
    // consume the entry.
    let stray = pub_.note_ack(1, 0b1, other);
    assert!(stray.placed.is_empty() && stray.refused.is_empty());
    assert!(
        pub_.in_flight.contains_key(&1),
        "entry survives a stray ack"
    );

    // An empty bitmap confirms nothing, but does resolve the request — and
    // must surrender the record so the round can be charged.
    pub_.in_flight.insert(
        2,
        EmberBatchInFlight {
            node_id: node,
            records: vec![a],
            deadline: std::time::Instant::now() + EMBER_BATCH_ACK_TIMEOUT,
        },
    );
    let refused = pub_.note_ack(2, 0, node);
    assert!(refused.placed.is_empty());
    assert_eq!(
        refused.refused,
        vec![a],
        "a record nobody took must not vanish silently"
    );
    assert!(!pub_.in_flight.contains_key(&2));

    let confirmed = pub_.note_ack(1, 0b1, node);
    assert_eq!(confirmed.placed, vec![a]);
    assert!(confirmed.refused.is_empty());
    assert!(pub_.in_flight.is_empty());
}

/// An ack that accepts nothing used to take neither the confirm path nor
/// the timeout path, so the file stayed marked as awaiting placement with
/// nothing left to resolve it — selection skipped it for the rest of the
/// session. It has to be charged like any other failed round.
#[test]
fn a_batch_every_storer_refuses_releases_the_file_for_another_round() {
    let mut pub_ = EmberBatchPublisher::default();
    let mut sched = TestSchedule::default();
    let node = ember::dht::EmberNodeId([9u8; 16]);
    let reference = record_ref(0xCD, 3);
    let slot = (reference.file_hash, reference.kind);
    let now = std::time::Instant::now();

    track_ember_record_pending(sched.borrow(), reference);
    pub_.in_flight.insert(
        4,
        EmberBatchInFlight {
            node_id: node,
            records: vec![reference],
            deadline: now + EMBER_BATCH_ACK_TIMEOUT,
        },
    );

    let outcome = pub_.note_ack(4, 0, node);
    assert_eq!(outcome.refused, vec![reference]);
    for reference in outcome.refused {
        fail_ember_record_pending(sched.borrow(), reference, now);
    }

    assert_eq!(sched.rounds_failed(reference), 1);
    assert!(
        !sched.unplaced.contains_key(&slot),
        "the file must be selectable again rather than stuck pending"
    );
}

/// The mirror case: one storer refusing must not charge a file another
/// storer already accepted.
#[test]
fn a_refusal_after_a_confirmation_does_not_charge_the_file() {
    let mut sched = TestSchedule::default();
    let reference = record_ref(0xCE, 4);
    let now = std::time::Instant::now();

    track_ember_record_pending(sched.borrow(), reference);
    // Another replica took it, which clears the pending set.
    sched.unplaced.remove(&(reference.file_hash, reference.kind));

    fail_ember_record_pending(sched.borrow(), reference, now);
    assert_eq!(sched.rounds_failed(reference), 0);
}

/// One replica's refusal must not drop the pending set while another
/// replica's batch is still in flight.
#[test]
fn a_refusal_does_not_clear_unplaced_while_another_replica_is_in_flight() {
    let mut pub_ = EmberBatchPublisher::default();
    let mut sched = TestSchedule::default();
    let a = ember::dht::EmberNodeId([1u8; 16]);
    let b = ember::dht::EmberNodeId([2u8; 16]);
    let reference = record_ref(0xCF, 5);
    let slot = (reference.file_hash, reference.kind);
    let now = std::time::Instant::now();

    track_ember_record_pending(sched.borrow(), reference);
    pub_.in_flight.insert(
        1,
        EmberBatchInFlight {
            node_id: a,
            records: vec![reference],
            deadline: now + EMBER_BATCH_ACK_TIMEOUT,
        },
    );
    pub_.in_flight.insert(
        2,
        EmberBatchInFlight {
            node_id: b,
            records: vec![reference],
            deadline: now + EMBER_BATCH_ACK_TIMEOUT,
        },
    );

    let outcome = pub_.note_ack(1, 0, a);
    assert_eq!(outcome.refused, vec![reference]);
    assert!(pub_.record_still_outstanding(reference));
    for reference in outcome.refused {
        if pub_.record_still_outstanding(reference) {
            continue;
        }
        fail_ember_record_pending(sched.borrow(), reference, now);
    }
    assert!(
        sched.unplaced.contains_key(&slot),
        "the other replica may still place the record"
    );
    assert_eq!(sched.rounds_failed(reference), 0);

    let placed = pub_.note_ack(2, 0b1, b);
    assert_eq!(placed.placed, vec![reference]);
    for reference in placed.placed {
        let slot = (reference.file_hash, reference.kind);
        if let Some(unplaced) = sched.unplaced.get_mut(&slot) {
            unplaced.remove(&reference.key);
            if unplaced.is_empty() {
                sched.unplaced.remove(&slot);
            }
        }
    }
    assert!(
        !sched.unplaced.contains_key(&slot),
        "the accepting replica must still be able to retire the file"
    );
    assert_eq!(sched.rounds_failed(reference), 0);
}

/// A storer accepts a batch record by record, so a partial acceptance
/// must confirm exactly the records whose bits are set — not all of them
/// because one landed.
#[test]
fn a_partial_batch_ack_confirms_only_the_accepted_records() {
    let mut pub_ = EmberBatchPublisher::default();
    let node = ember::dht::EmberNodeId([7u8; 16]);
    let refs: Vec<EmberRecordRef> = (0..5u8).map(|i| record_ref(0xAB, i)).collect();

    pub_.in_flight.insert(
        9,
        EmberBatchInFlight {
            node_id: node,
            records: refs.clone(),
            deadline: std::time::Instant::now() + EMBER_BATCH_ACK_TIMEOUT,
        },
    );

    // Records 0, 2 and 4 accepted; 1 and 3 rejected.
    let outcome = pub_.note_ack(9, 0b10101, node);
    assert_eq!(outcome.placed, vec![refs[0], refs[2], refs[4]]);
    assert_eq!(
        outcome.refused,
        vec![refs[1], refs[3]],
        "the rejected half is reported so the round can be charged"
    );
}

/// The queue's running count must track its contents exactly, or the cap
/// either stops admitting work or stops bounding it.
#[test]
fn the_publish_queue_count_tracks_its_contents() {
    let mut pub_ = EmberBatchPublisher::default();
    let targets: Vec<ember::dht::EmberContact> = (1..=3u8)
        .map(|i| ember::dht::EmberContact {
            node_id: ember::dht::EmberNodeId([i; 16]),
            addr: SocketAddr::from(([80, i, 1, 1], 4672)),
            noise_pub: [i; 32],
            ed25519_pub: [i; 32],
            last_seen: 1,
            failed_queries: 0,
        })
        .collect();
    let record = ember::dht::messages::BatchedRecord {
        key: [9u8; 16],
        record: vec![1, 2, 3],
        record_signature: [0u8; 64],
    };

    for i in 0..4u8 {
        assert!(pub_.enqueue(&targets, record_ref(1, i), record.clone()));
    }
    let actual: usize = pub_.queued.values().map(|(_, v)| v.len()).sum();
    assert_eq!(pub_.queued_count, actual);
    assert_eq!(actual, 12, "four records across three targets");

    pub_.clear();
    assert_eq!(pub_.queued_count, 0);
    assert!(pub_.queued.is_empty());

    // And the cap actually stops admitting once reached.
    pub_.queued_count = EMBER_BATCH_QUEUE_MAX;
    assert!(!pub_.enqueue(&targets, record_ref(2, 0), record));
    assert!(
        pub_.queued.is_empty(),
        "the cap must refuse work rather than growing without bound"
    );
}

/// An unanswered batch must not linger in the in-flight map, and must
/// surrender its records so the backoff can be charged against them.
#[test]
fn unacked_batches_expire() {
    let mut pub_ = EmberBatchPublisher::default();
    pub_.in_flight.insert(
        1,
        EmberBatchInFlight {
            node_id: ember::dht::EmberNodeId([1u8; 16]),
            records: vec![record_ref(0, 0)],
            deadline: std::time::Instant::now() - EMBER_BATCH_ACK_TIMEOUT,
        },
    );
    let abandoned = pub_.expire(std::time::Instant::now());
    assert!(pub_.in_flight.is_empty());
    assert_eq!(abandoned, vec![record_ref(0, 0)]);
}

/// A batch queued behind Noise keeps the handshake budget on top of the
/// ordinary 30s ack window, so expire does not reap it before the session
/// can flush and the ACK can land.
#[test]
fn a_queued_batch_uses_the_handshake_extended_deadline() {
    let now = std::time::Instant::now();
    let sent = ember_batch_ack_deadline(now, false);
    let queued = ember_batch_ack_deadline(now, true);
    assert_eq!(
        queued.duration_since(sent),
        EMBER_SEARCH_QUEUED_QUERY_TIMEOUT
    );

    let mut pub_ = EmberBatchPublisher::default();
    pub_.in_flight.insert(
        1,
        EmberBatchInFlight {
            node_id: ember::dht::EmberNodeId([1u8; 16]),
            records: vec![record_ref(0, 0)],
            deadline: queued,
        },
    );
    assert!(
        pub_.expire(now + EMBER_BATCH_ACK_TIMEOUT).is_empty(),
        "the ordinary 30s window must not reap a handshake-queued batch"
    );
    assert_eq!(pub_.in_flight.len(), 1);
    let abandoned = pub_.expire(queued);
    assert!(pub_.in_flight.is_empty());
    assert_eq!(abandoned, vec![record_ref(0, 0)]);
}

/// The four maps `EmberPublishSchedule` borrows, owned so a test can drive
/// the state machine without a whole `NetworkState`.
#[derive(Default)]
struct TestSchedule {
    unplaced: HashMap<([u8; 16], EmberPublishKind), HashSet<[u8; 16]>>,
    attempts: HashMap<([u8; 16], EmberPublishKind), EmberPublishAttempts>,
    source_at: HashMap<[u8; 16], std::time::Instant>,
    keyword_at: HashMap<[u8; 16], std::time::Instant>,
}

impl TestSchedule {
    fn borrow(&mut self) -> EmberPublishSchedule<'_> {
        EmberPublishSchedule {
            unplaced: &mut self.unplaced,
            attempts: &mut self.attempts,
            source_at: &mut self.source_at,
            keyword_at: &mut self.keyword_at,
        }
    }

    fn rounds_failed(&self, reference: EmberRecordRef) -> u32 {
        self.attempts
            .get(&(reference.file_hash, reference.kind))
            .map(|a| a.rounds_failed)
            .unwrap_or(0)
    }
}

/// Records the flush gave up on never reached a peer, so they must not count
/// against the file. Charging at selection meant three ticks of discarded
/// records parked a file for a full republish interval with nothing having
/// left the host — and because the clock was stamped, it looked published.
#[test]
fn dropped_records_cost_a_file_nothing() {
    let mut sched = TestSchedule::default();
    let one = record_ref(1, 10);
    let two = record_ref(1, 11);
    let slot = (one.file_hash, one.kind);

    track_ember_record_pending(sched.borrow(), one);
    track_ember_record_pending(sched.borrow(), two);
    assert_eq!(sched.unplaced[&slot].len(), 2);

    // The flush could not send either of them.
    untrack_ember_record_pending(sched.borrow(), one);
    untrack_ember_record_pending(sched.borrow(), two);

    assert_eq!(
        sched.rounds_failed(one),
        0,
        "a dropped round is not a failure"
    );
    assert!(
        !sched.unplaced.contains_key(&slot),
        "the file must leave the pending set or selection never offers it again"
    );
    assert!(
        !sched.keyword_at.contains_key(&one.file_hash),
        "nothing was placed, so the republish clock must not have advanced"
    );

    // And it is due again straight away rather than waiting out an interval.
    assert_eq!(
        ember_publish_staleness(
            &sched.unplaced,
            &sched.keyword_at,
            one.file_hash,
            one.kind,
            EMBER_KEYWORD_REPUBLISH,
            std::time::Instant::now(),
        ),
        Some(u64::MAX)
    );
}

/// Only records that reached the wire and went unacked count, and one round
/// counts once however many of its `K_EMBER_REPLICAS` batches time out.
#[test]
fn a_failed_round_is_charged_once_and_parks_the_file_after_three() {
    let mut sched = TestSchedule::default();
    let reference = record_ref(2, 20);
    let slot = (reference.file_hash, reference.kind);
    let start = std::time::Instant::now();

    track_ember_record_pending(sched.borrow(), reference);

    // A round's replica batches all time out together; that is one round.
    for _ in 0..5 {
        fail_ember_record_pending(sched.borrow(), reference, start);
    }
    assert_eq!(sched.rounds_failed(reference), 1);

    // A charge short of the cap releases the placement hold, which is what
    // lets the next tick select the file and produce another round. Left
    // held, the file was never re-selected, never produced another batch,
    // and so never reached `expire()` for a second charge — `rounds_failed`
    // froze at 1 and the file sat out the rest of the session.
    assert!(
        !sched.unplaced.contains_key(&slot),
        "a failed round must release the file for re-selection"
    );

    // Later rounds are a publish tick apart, well outside the collapse
    // window, so they count separately. Each begins by re-selecting the
    // file, exactly as `maybe_publish_ember_*` would.
    let mut at = start;
    for expected in 2..=EMBER_PUBLISH_MAX_ATTEMPTS {
        at += EMBER_BATCH_ACK_TIMEOUT * 2;
        track_ember_record_pending(sched.borrow(), reference);
        fail_ember_record_pending(sched.borrow(), reference, at);
        assert_eq!(sched.rounds_failed(reference), expected);
    }

    // One more parks it: the clock is stamped so the staleness ranking stops
    // putting it first, and the pending marker is released.
    at += EMBER_BATCH_ACK_TIMEOUT * 2;
    track_ember_record_pending(sched.borrow(), reference);
    fail_ember_record_pending(sched.borrow(), reference, at);
    assert!(!sched.unplaced.contains_key(&slot));
    assert!(sched.keyword_at.contains_key(&reference.file_hash));
    assert_eq!(
        ember_publish_staleness(
            &sched.unplaced,
            &sched.keyword_at,
            reference.file_hash,
            reference.kind,
            EMBER_KEYWORD_REPUBLISH,
            at,
        ),
        None,
        "a parked file waits out its interval"
    );

    // A straggling timeout after the round resolved must not re-charge it.
    at += EMBER_BATCH_ACK_TIMEOUT * 2;
    fail_ember_record_pending(sched.borrow(), reference, at);
    assert_eq!(sched.rounds_failed(reference), 0);
}

/// Selection ranks on the republish clock, which says nothing about whether
/// the previous round is still in flight. Without the pending check a file
/// was picked again every tick and put a second copy of every record on the
/// wire — and carry-over means a backlog legitimately spans several ticks.
#[test]
fn a_file_awaiting_placement_is_not_selected_again() {
    let mut sched = TestSchedule::default();
    let reference = record_ref(3, 30);
    let now = std::time::Instant::now();

    // Never published: maximally stale, so certain to be picked.
    assert_eq!(
        ember_publish_staleness(
            &sched.unplaced,
            &sched.keyword_at,
            reference.file_hash,
            reference.kind,
            EMBER_KEYWORD_REPUBLISH,
            now,
        ),
        Some(u64::MAX)
    );

    // Queued for a peer: still maximally stale by the clock, but off-limits.
    track_ember_record_pending(sched.borrow(), reference);
    assert_eq!(
        ember_publish_staleness(
            &sched.unplaced,
            &sched.keyword_at,
            reference.file_hash,
            reference.kind,
            EMBER_KEYWORD_REPUBLISH,
            now,
        ),
        None
    );

    // Confirmed placement releases it, and then the interval holds it back.
    untrack_ember_record_pending(sched.borrow(), reference);
    sched
        .borrow()
        .stamp(reference.file_hash, reference.kind, now);
    assert_eq!(
        ember_publish_staleness(
            &sched.unplaced,
            &sched.keyword_at,
            reference.file_hash,
            reference.kind,
            EMBER_KEYWORD_REPUBLISH,
            now,
        ),
        None
    );
    assert!(
        ember_publish_staleness(
            &sched.unplaced,
            &sched.keyword_at,
            reference.file_hash,
            reference.kind,
            EMBER_KEYWORD_REPUBLISH,
            now + EMBER_KEYWORD_REPUBLISH,
        )
        .is_some(),
        "once the interval has passed it is due again"
    );
}

#[test]
fn ember_publish_instant_treats_never_and_expired_as_due() {
    let now = std::time::Instant::now();
    let interval = std::time::Duration::from_secs(2 * 3600);
    let now_unix = 1_700_000_000i64;
    assert!(ember_publish_instant(0, now_unix, now, interval).is_none());
    assert!(ember_publish_instant(
        (now_unix as u32).saturating_sub(interval.as_secs() as u32),
        now_unix,
        now,
        interval,
    )
    .is_none());
    assert!(ember_publish_instant(
        (now_unix as u32).saturating_sub(interval.as_secs() as u32 + 60),
        now_unix,
        now,
        interval,
    )
    .is_none());
}

#[test]
fn ember_publish_instant_keeps_a_stamp_still_inside_the_interval() {
    let now = std::time::Instant::now();
    let interval = std::time::Duration::from_secs(2 * 3600);
    let now_unix = 1_700_000_000i64;
    let last = (now_unix as u32).saturating_sub(60);
    let at = ember_publish_instant(last, now_unix, now, interval)
        .expect("a one-minute-old stamp must still be scheduled");
    let elapsed = now.duration_since(at).as_secs();
    assert!(
        elapsed <= 60 + 2,
        "hydrated Instant should be ~60s ago, got {elapsed}s"
    );
}

#[test]
fn note_ember_verified_contacts_tracks_daily_and_alltime_peaks() {
    let mut hw = EmberVerifiedHighwater {
        day: chrono::Utc::now().date_naive().to_string(),
        daily: 3,
        alltime: 10,
    };
    assert!(note_ember_verified_contacts(&mut hw, 12));
    assert_eq!(hw.daily, 12);
    assert_eq!(hw.alltime, 12);
    assert!(!note_ember_verified_contacts(&mut hw, 8));
    assert_eq!(hw.daily, 12);
    assert_eq!(hw.alltime, 12);
}

/// A ping is the only way a lead becomes usable, so the ping budget is also
/// the join rate. The steady-state trickle made a cold join take many
/// minutes, during which publishes had one target and lookups one seed.
#[test]
fn a_starved_table_gets_a_wider_ping_budget() {
    let starved = EMBER_PING_STARVED_BELOW;
    assert_eq!(ember_maint_ping_budget(0, 0), EMBER_MAINT_MAX_PINGS_STARVED);
    assert_eq!(
        ember_maint_ping_budget(starved - 1, starved - 1),
        EMBER_MAINT_MAX_PINGS_STARVED
    );
    // Once joined, a small table drops back to the steady-state trickle.
    assert_eq!(
        ember_maint_ping_budget(starved, starved),
        EMBER_MAINT_MAX_PINGS
    );
    const _: () = assert!(EMBER_MAINT_MAX_PINGS_STARVED > EMBER_MAINT_MAX_PINGS);
}

/// The budget used to be one absolute rate for every table size, so a full
/// table took hours to work through and contacts in buckets no lookup
/// touched stayed dead until the much later stale sweep.
#[test]
fn the_ping_budget_follows_the_size_of_the_table() {
    let joined = EMBER_PING_STARVED_BELOW;
    let full = ember::dht::K_BUCKET_SIZE * ember::dht::ID_BITS;

    let small = ember_maint_ping_budget(joined, 60);
    let large = ember_maint_ping_budget(joined, 600);
    assert!(
        large > small,
        "a bigger table has more to check, so it must check more"
    );

    // Never below the old trickle, and never above a rate the join path
    // already sustains.
    for contacts in [0, 1, 60, 600, 6_000, full, usize::MAX] {
        let budget = ember_maint_ping_budget(joined, contacts);
        assert!(
            (EMBER_MAINT_MAX_PINGS..=EMBER_MAINT_MAX_PINGS_STARVED).contains(&budget),
            "{contacts} contacts produced {budget}"
        );
    }
}

fn queued_record(seed: u8) -> EmberQueuedRecord {
    EmberQueuedRecord {
        reference: record_ref(1, seed),
        record: ember::dht::messages::BatchedRecord {
            key: [seed; 16],
            record: vec![seed, seed, seed],
            record_signature: [0u8; 64],
        },
    }
}

/// The flush's frame budget used to discard whatever it could not send,
/// while the file had already been charged an attempt at selection — three
/// ticks of that parked a file for a whole republish interval with none of
/// its records ever having left the host.
#[test]
fn a_flush_holds_over_what_it_could_not_send() {
    let mut pub_ = EmberBatchPublisher::default();
    let node = ember::dht::EmberNodeId([7u8; 16]);
    let contact = ember::dht::EmberContact {
        node_id: node,
        addr: SocketAddr::from(([80, 7, 1, 1], 4672)),
        noise_pub: [7u8; 32],
        ed25519_pub: [7u8; 32],
        last_seen: 1,
        failed_queries: 0,
    };

    let tail: Vec<EmberQueuedRecord> = (0..5u8).map(queued_record).collect();
    let dropped = pub_.carry_over(node, &contact, tail);
    assert!(dropped.is_empty(), "there was room for all of it");
    assert_eq!(pub_.queued_count, 5);
    assert_eq!(pub_.queued[&node].1.len(), 5);

    // Held-over work stays ahead of anything queued afterwards, so the
    // oldest records are still the first ones tried.
    pub_.enqueue(
        std::slice::from_ref(&contact),
        record_ref(2, 99),
        queued_record(99).record,
    );
    let order: Vec<[u8; 16]> = pub_.queued[&node]
        .1
        .iter()
        .map(|q| q.reference.key)
        .collect();
    assert_eq!(order.last(), Some(&record_ref(2, 99).key));
    assert_eq!(order.len(), 6);
}

/// The flush runs every `EMBER_FLUSH_INTERVAL`, so the per-minute ceiling
/// only holds if each pass charges what it committed. A frame queued
/// behind a Noise handshake was charged nothing, which meant the next
/// flush six seconds later saw the whole allowance again and a cold peer
/// could be committed several times over before its handshake finished.
///
/// The budget is a *trailing* window now, mirroring the storer's own gate
/// (`ember::dht::protection::WindowCounter`) — the two have to use the same
/// model or the pacing is fiction, and a storer refusing an over-budget
/// frame discards the whole batch without acking it. So the property is no
/// longer "spent for exactly a minute, then a clean jump"; it is "charged
/// immediately, returned gradually, and never handed back in full inside
/// the window".
///
/// Queried in forward time order throughout: `record_allowance` ages the
/// buckets as a side effect, so going backwards would read a window that
/// has already rolled past that instant.
#[test]
fn a_committed_batch_is_charged_and_returns_only_gradually() {
    let mut pub_ = EmberBatchPublisher::default();
    let node = ember::dht::EmberNodeId([5u8; 16]);
    let now = std::time::Instant::now();
    let per_minute = EMBER_STORE_RECORDS_PER_PEER_PER_MIN as usize;

    assert_eq!(pub_.record_allowance(node, now), per_minute);
    pub_.note_records_sent(node, now, per_minute);

    // The original bug: the very next flush saw the whole budget again.
    assert_eq!(
        pub_.record_allowance(node, now + EMBER_FLUSH_INTERVAL),
        0,
        "a committed batch must be charged straight away"
    );

    // Walk the rest of the window forward. It may return budget gradually,
    // but must never offer a fresh full allowance inside it.
    let mut at = now + EMBER_FLUSH_INTERVAL;
    let mut saw_partial_return = false;
    while at.duration_since(now) < std::time::Duration::from_secs(60) {
        let allowance = pub_.record_allowance(node, at);
        assert!(
            allowance < per_minute,
            "a full budget was offered {:?} into the window",
            at.duration_since(now)
        );
        if allowance > 0 {
            saw_partial_return = true;
        }
        at += EMBER_FLUSH_INTERVAL;
    }
    assert!(
        saw_partial_return,
        "a trailing window should hand budget back gradually, not in one jump"
    );

    // A full window of silence restores it completely.
    assert_eq!(
        pub_.record_allowance(node, now + std::time::Duration::from_secs(200)),
        per_minute
    );
}

/// Carry-over must not become an unbounded spool: one peer that never
/// drains would fill the global queue cap and starve every other
/// destination's publishes.
#[test]
fn carry_over_is_bounded_per_peer() {
    let mut pub_ = EmberBatchPublisher::default();
    let node = ember::dht::EmberNodeId([8u8; 16]);
    let contact = ember::dht::EmberContact {
        node_id: node,
        addr: SocketAddr::from(([80, 8, 1, 1], 4672)),
        noise_pub: [8u8; 32],
        ed25519_pub: [8u8; 32],
        last_seen: 1,
        failed_queries: 0,
    };

    let over = EMBER_MAX_CARRY_OVER_PER_PEER + 40;
    let tail: Vec<EmberQueuedRecord> = (0..over).map(|i| queued_record(i as u8)).collect();
    let dropped = pub_.carry_over(node, &contact, tail);
    assert_eq!(
        dropped.len(),
        40,
        "the excess is reported, not silently lost"
    );
    assert_eq!(pub_.queued_count, EMBER_MAX_CARRY_OVER_PER_PEER);
    assert_eq!(
        pub_.queued[&node].1.len(),
        EMBER_MAX_CARRY_OVER_PER_PEER,
        "the peer holds its limit and no more"
    );
}

/// A fixed per-tick budget silently stopped republishing everything past
/// a few thousand files, because the cycle no longer fit inside the
/// record TTL.
/// A table big enough that the deliverable bound is not what binds, so
/// these cases exercise the TTL arithmetic rather than the flush budget.
const ROOMY_TABLE: usize = K_EMBER_REPLICAS * 64;

/// A room busy enough to spend the relay allowance must still be able to
/// carry what this user typed.
///
/// The two buckets are what make that true, so this exhausts the relay one
/// and checks the local one is untouched. Sharing a bucket was the bug: the
/// local copy of a line is written and drawn before fanout is even
/// attempted, so a send refused here leaves the user looking at a message
/// no peer will ever be offered again.
#[test]
fn a_saturated_relay_budget_cannot_swallow_what_the_user_typed() {
    let mut relayed = VecDeque::new();
    let mut local = VecDeque::new();
    let now = std::time::Instant::now();

    for _ in 0..ember::channel::CHANNEL_GOSSIP_OUT_PER_SEC {
        assert!(ember::channel::rate_window_allow(
            &mut relayed,
            now,
            CHANNEL_GOSSIP_RATE_WINDOW,
            ember::channel::CHANNEL_GOSSIP_OUT_PER_SEC,
        ));
    }
    assert!(
        !ember::channel::rate_window_allow(
            &mut relayed,
            now,
            CHANNEL_GOSSIP_RATE_WINDOW,
            ember::channel::CHANNEL_GOSSIP_OUT_PER_SEC,
        ),
        "the relay allowance is meant to run out, that is what stops a flood"
    );

    assert!(
        ember::channel::rate_window_allow(
            &mut local,
            now,
            CHANNEL_GOSSIP_RATE_WINDOW,
            ember::channel::CHANNEL_GOSSIP_LOCAL_PER_SEC,
        ),
        "originating must not be charged the allowance relaying just spent"
    );
}

/// A room nobody else is in yet must be re-asked on a cadence a waiting
/// user would accept, and the driver that applies it has to tick at least
/// that often or the constant is decoration. `maybe_refresh_channel_members`
/// moved off the sixty-second maintenance tick onto the one-second one for
/// exactly this reason; putting it back would silently round the empty-room
/// interval up to a minute while every value here still read as intended.
///
/// `member_count` is presence-fresh (including us). Historical roster rows
/// do not keep the slow interval — 1 means nobody else has announced
/// recently, which is the empty-room poll case.
#[test]
fn an_empty_room_asks_for_its_roster_far_sooner_than_a_settled_one() {
    let empty = channel_presence_interval(1, false);
    let settled = channel_presence_interval(4, false);

    assert_eq!(empty, ember::channel::PRESENCE_FETCH_EMPTY_SECS);
    assert_eq!(settled, ember::channel::PRESENCE_FETCH_SECS);
    assert!(
        empty < settled,
        "an empty room is the case somebody is waiting on"
    );
    // Zero should not be reachable — we write our own member row on join —
    // but it is the same "nobody else" situation if it ever is.
    assert_eq!(channel_presence_interval(0, false), empty);
    assert!(
        empty < ember::channel::PRESENCE_REPUBLISH_SECS,
        "asking less often than members announce would miss arrivals"
    );
}

/// The room on screen is walked at the watched rate however settled it is.
///
/// A busy room takes the five-minute interval from its member count, which
/// is right for the twenty-nine rooms nobody is reading and wrong for the
/// one that is open: five minutes is simply how long a new arrival stays
/// invisible to the person looking straight at the member list.
#[test]
fn the_room_on_screen_is_walked_at_the_watched_rate() {
    assert_eq!(
        channel_presence_interval(40, true),
        ember::channel::PRESENCE_FETCH_FOCUSED_SECS
    );
    assert!(
        channel_presence_interval(40, true) < channel_presence_interval(40, false),
        "focus has to beat the settled interval or naming the open room buys nothing"
    );
}

#[test]
fn keyword_publish_budget_covers_the_library_within_its_ttl() {
    let ticks_per_cycle =
        (EMBER_KEYWORD_REPUBLISH.as_secs() / EMBER_MAINT_INTERVAL.as_secs()) as usize;

    // A small library still gets the floor rather than zero.
    assert_eq!(
        ember_keyword_files_per_tick(0, ROOMY_TABLE),
        EMBER_KEYWORD_PUBLISH_MIN_PER_TICK
    );
    assert_eq!(
        ember_keyword_files_per_tick(1, ROOMY_TABLE),
        EMBER_KEYWORD_PUBLISH_MIN_PER_TICK
    );

    // Libraries up to the point where the ceiling binds must complete a
    // full pass inside one republish interval.
    for library in [1_000usize, 10_000, 50_000] {
        let per_tick = ember_keyword_files_per_tick(library, ROOMY_TABLE);
        let covered = per_tick * ticks_per_cycle;
        if per_tick < EMBER_KEYWORD_PUBLISH_MAX_PER_TICK {
            assert!(
                covered >= library,
                "a {library}-file library publishes {per_tick}/tick, covering only \
                 {covered} within the republish interval"
            );
        }
    }

    // And the ceiling still bounds a single tick's burst.
    assert_eq!(
        ember_keyword_files_per_tick(usize::MAX / 2, ROOMY_TABLE),
        EMBER_KEYWORD_PUBLISH_MAX_PER_TICK
    );
}

/// A digest a transfer will *enforce* has to be corroborated, because getting
/// it wrong is unrecoverable: the content check fails at completion and reopens
/// every part, on every retry, forever. The source path already required two
/// agreeing publishers. A keyword *row* may show a plurality of one so the
/// user can pin it by clicking download; automatic search seeding must not.
#[test]
fn one_publisher_cannot_seed_a_digest_a_transfer_will_enforce() {
    use ed25519_dalek::SigningKey;

    let liar = SigningKey::from_bytes(&[0x11; 32]);
    let honest_a = SigningKey::from_bytes(&[0x22; 32]);
    let honest_b = SigningKey::from_bytes(&[0x33; 32]);
    let poisoned = [0xAAu8; 16];
    let agreed = [0xBBu8; 16];
    let junk = [0x99u8; 32];
    let real = [0x77u8; 32];

    let blobs = vec![
        // One publisher, one claim: displayable, never auto-enforced.
        ember_kw_blob_with_digest(&liar, "ubuntu", poisoned, junk, 100, "ubuntu.iso"),
        // Two publishers agreeing: enforceable.
        ember_kw_blob_with_digest(&honest_a, "ubuntu", agreed, real, 100, "ubuntu-24.iso"),
        ember_kw_blob_with_digest(&honest_b, "ubuntu", agreed, real, 100, "ubuntu-24.iso"),
    ];
    let built = build_ember_keyword_built(&blobs, &["ubuntu".to_string()], None);

    assert_eq!(built.results.len(), 2, "both files are still shown");
    let shown = built
        .results
        .iter()
        .find(|r| r.file.hash == hex::encode(poisoned))
        .expect("the single-publisher file is displayed");
    assert_eq!(
        shown.file.ember_file_hash,
        hex::encode(junk),
        "a unique digest is shown so a click can pin it"
    );
    assert!(
        built
            .corroborated
            .iter()
            .all(|(hash, _, _)| *hash != poisoned),
        "an uncorroborated digest must not auto-seed the enforced map"
    );

    let agreed_row = built
        .results
        .iter()
        .find(|r| r.file.hash == hex::encode(agreed))
        .expect("the corroborated file is displayed");
    assert_eq!(
        agreed_row.file.ember_file_hash,
        hex::encode(real),
        "a digest two publishers agree on is carried"
    );
    assert!(
        built
            .corroborated
            .iter()
            .any(|(hash, digest, publishers)| {
                *hash == agreed && *digest == real && *publishers == 2
            }),
        "a corroborated digest is what automatic seeding may pin"
    );
}

/// The backpressure gate compares a queue counted in *(record x replica)*
/// entries against a budget counted in records, so the two have to be brought
/// into the same unit. They were not, and the gate was therefore up to
/// `K_EMBER_REPLICAS` times too strict — on a twenty-contact table it called a
/// backlog at six records.
///
/// That silently switched keyword publishing off. Source selection runs first
/// and leaves its fan-out queued; keyword selection runs second behind the same
/// gate and returned without doing anything, on every tick, for any library
/// past a few hundred files after a restart. Sources kept flowing, so the files
/// stayed downloadable by hash while leaving search entirely.
#[test]
fn the_backpressure_gate_counts_queue_entries_not_records() {
    for contacts in [1usize, 5, K_EMBER_REPLICAS, K_EMBER_REPLICAS * 4] {
        let threshold = ember_publish_backpressure_threshold(contacts);
        let deliverable = ember_deliverable_records_per_tick(contacts);

        // The gate itself, either side of its threshold.
        assert!(
            !ember_publish_queue_is_backed_up_at(threshold - 1, contacts),
            "a tick's own fan-out is not a backlog at {contacts} contacts"
        );
        assert!(
            ember_publish_queue_is_backed_up_at(threshold, contacts),
            "and the threshold itself does read as one"
        );

        // The old gate compared against the record count directly, which at
        // any real table size trips while a single tick's fan-out is still in
        // the queue.
        if contacts > 1 {
            assert!(
                threshold > deliverable,
                "at {contacts} contacts a record occupies several queue entries, \
                 so comparing against {deliverable} alone trips far too early"
            );
            assert!(
                !ember_publish_queue_is_backed_up_at(deliverable, contacts),
                "one tick of records must not read as a backlog"
            );
        }

        // And it can never grow past what the queue itself will hold, or it
        // stops being a gate at all.
        assert!(threshold <= EMBER_BATCH_QUEUE_MAX / 2);
    }
}

/// The keyword budget used to ignore what the flush could carry. On a small
/// table every key resolves to the same handful of peers, so 96 files of
/// several records each was hundreds of records aimed at a destination that
/// could take a few dozen — and the rest was discarded while each file was
/// charged a publish attempt.
#[test]
fn publish_budgets_stay_within_what_the_flush_can_deliver() {
    // A one-contact table: every record goes to that one peer, so the
    // deliverable total is one peer's minute of allowance.
    assert_eq!(
        ember_deliverable_records_per_tick(1),
        EMBER_STORE_RECORDS_PER_PEER_PER_MIN as usize
    );
    assert_eq!(
        ember_deliverable_records_per_tick(K_EMBER_REPLICAS),
        EMBER_STORE_RECORDS_PER_PEER_PER_MIN as usize
    );
    // Past k the target sets diverge and the total scales with the table.
    assert!(
        ember_deliverable_records_per_tick(K_EMBER_REPLICAS * 4)
            > ember_deliverable_records_per_tick(K_EMBER_REPLICAS)
    );

    // A huge library on a tiny table must be held to the deliverable count,
    // counting each file as several keyword records.
    let tiny = ember_keyword_files_per_tick(50_000, 1);
    assert!(
        tiny * EMBER_KEYWORDS_PER_FILE_ESTIMATE <= ember_deliverable_records_per_tick(1),
        "{tiny} files of ~{EMBER_KEYWORDS_PER_FILE_ESTIMATE} records each exceeds \
         what one peer will accept"
    );
    assert!(tiny < EMBER_KEYWORD_PUBLISH_MAX_PER_TICK);

    // Sources are one record per file, so they get the whole allowance.
    let tiny_src = ember_source_files_per_tick(50_000, 50_000, 1);
    assert!(tiny_src <= ember_deliverable_records_per_tick(1));
    assert!(
        tiny_src > tiny,
        "a source file is cheaper than a keyword file"
    );

    // And a roomy table is not what binds: the same library gets more per
    // tick than it would on a table of one, because the records spread.
    assert!(
        ember_keyword_files_per_tick(50_000, ROOMY_TABLE) > tiny,
        "a roomy table should not be held to the one-contact deliverable bound"
    );
    assert_eq!(
        ember_keyword_files_per_tick(usize::MAX / 2, ROOMY_TABLE),
        EMBER_KEYWORD_PUBLISH_MAX_PER_TICK,
        "the hard ceiling still bounds the extreme"
    );
}

/// A ban earned by timing alone must not outlive eMule's `CLIENTBANTIME`,
/// and it must agree with the in-memory tracker that granted it — those two
/// disagreed, so `AbuseTracker` considered a peer forgiven after two hours
/// while the persisted mirror kept its address blocked for a week. Because
/// the key is an IP, that week fell on every client behind it.
#[test]
fn a_timing_ban_lasts_emules_two_hours_not_a_week() {
    assert_eq!(
        AUTO_BAN_TTL_BEHAVIOUR_SECS, 2 * 3600,
        "eMule CLIENTBANTIME (Opcodes.h:122)"
    );
    assert_eq!(
        AUTO_BAN_TTL_BEHAVIOUR_SECS,
        crate::network::ed2k::upload::BAN_DURATION_SECS,
        "the persisted lifetime and the in-memory tracker's must be one number"
    );
    // Content evidence keeps the long ban; that the two stay distinct is
    // pinned at compile time beside the constants.
    assert_eq!(AUTO_BAN_TTL_CONTENT_SECS, 7 * 24 * 3600);
}

/// The server accounts for source requests per connection, so the ceiling
/// has to match eMule's arithmetic exactly rather than approximately: 15
/// hashes per frame and one frame per 300 s (`DownloadQueue.cpp:1307`,
/// `:1387`, whose comment reads "server credits: 16 * iMaxFilesPerTcpFrame +
/// 1 = 241"). Three separate Ember paths used to send `OP_GETSOURCES` on
/// their own clocks, reaching roughly 40 a minute against eMule's 3.
#[test]
fn server_source_requests_match_emules_credit_ceiling() {
    assert_eq!(SERVER_TCP_SRCREQ_MAX_PER_FRAME, 15);
    assert_eq!(SERVER_TCP_SRCREQ_INTERVAL_SECS, 300);
    // The starved clock's relationship to the interval is pinned at compile
    // time next to the constants themselves.

    // Worst case across every path is one frame per interval.
    let per_minute =
        60.0 * SERVER_TCP_SRCREQ_MAX_PER_FRAME as f64 / SERVER_TCP_SRCREQ_INTERVAL_SECS as f64;
    assert!(
        per_minute <= 3.0,
        "{per_minute} source requests/minute exceeds eMule's ceiling of 3"
    );
}

/// Both candidate buddy ports have to be reachable across a row's retry
/// budget, but never within one attempt: two `KADEMLIA_CALLBACK_REQ`s to one
/// IP exceed eMule's per-opcode budget, and the deficit compounds until the
/// buddy bans us for two hours — taking the callback route down with it.
#[test]
fn callback_retries_alternate_ports_instead_of_doubling_up() {
    let port = 4672u16;

    assert_eq!(kad_callback_buddy_port(port, 0), port);
    assert_eq!(kad_callback_buddy_port(port, 1), port + 3);
    assert_eq!(kad_callback_buddy_port(port, 2), port);
    assert_eq!(kad_callback_buddy_port(port, 3), port + 3);

    // Across the six tries `MAX_CALLBACK_REASKS` allows, each candidate has
    // to get a real share — one port winning every attempt would reproduce
    // the "failed ~100% against opposite-flavour publishers" bug.
    let tried: Vec<u16> = (0..6).map(|a| kad_callback_buddy_port(port, a)).collect();
    assert_eq!(tried.iter().filter(|p| **p == port).count(), 3);
    assert_eq!(tried.iter().filter(|p| **p == port + 3).count(), 3);

    // A port near the top of the range must not wrap into a low one.
    assert_eq!(kad_callback_buddy_port(u16::MAX, 1), u16::MAX);
}

/// Source records had the fixed budget the keyword path was already fixed
/// for: five per tick covers 600 files in the two-hour interval, so a
/// larger library never completed a pass and the remainder was never
/// published. A cold start also crawled — a 160-file library took half an
/// hour before its last file was findable.
#[test]
fn source_publish_budget_covers_the_library_and_drains_a_backlog() {
    let ticks_per_cycle =
        (EMBER_SOURCE_REPUBLISH.as_secs() / EMBER_MAINT_INTERVAL.as_secs()) as usize;

    // Nothing to do still yields the floor, not zero.
    assert_eq!(
        ember_source_files_per_tick(0, 0, ROOMY_TABLE),
        EMBER_SOURCE_PUBLISH_MIN_PER_TICK
    );

    // Steady state: one full pass must fit the republish interval for
    // every library the ceiling can still cover.
    let coverable = EMBER_SOURCE_PUBLISH_MAX_PER_TICK * ticks_per_cycle;
    for library in [600usize, 1_000, coverable] {
        // Worst case for coverage is a spread-out schedule, where only an
        // interval's share is due on any one tick.
        let due = library.div_ceil(ticks_per_cycle);
        let per_tick = ember_source_files_per_tick(library, due, ROOMY_TABLE);
        assert!(
            per_tick * ticks_per_cycle >= library,
            "a {library}-file library publishes {per_tick}/tick, covering only \
             {} within the republish interval",
            per_tick * ticks_per_cycle
        );
    }

    // Cold start: a whole library due at once drains in about
    // `EMBER_SOURCE_BACKLOG_DRAIN_TICKS`, not a whole pass. The old fixed
    // five would have needed 32 ticks for this library.
    let per_tick = ember_source_files_per_tick(159, 159, ROOMY_TABLE);
    assert!(
        per_tick >= 159 / EMBER_SOURCE_BACKLOG_DRAIN_TICKS,
        "a 159-file backlog only publishes {per_tick}/tick"
    );
    assert!(per_tick > EMBER_SOURCE_PUBLISH_MIN_PER_TICK);

    // And a tick's burst stays bounded however big the backlog gets.
    assert_eq!(
        ember_source_files_per_tick(usize::MAX / 2, usize::MAX / 2, ROOMY_TABLE),
        EMBER_SOURCE_PUBLISH_MAX_PER_TICK
    );
}

#[test]
fn ember_keyword_results_dedup_counts_distinct_publishers() {
    let sk1 = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let sk2 = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
    let hash_a = [0xAAu8; 16];
    let hash_b = [0xBBu8; 16];
    // File A published by two distinct keypairs, file B by one.
    let blobs = vec![
        ember_kw_blob(&sk1, "ubuntu", hash_a, 100, "ubuntu-24.iso"),
        ember_kw_blob(&sk2, "ubuntu", hash_a, 100, "ubuntu-24.iso"),
        ember_kw_blob(&sk1, "ubuntu", hash_b, 200, "ubuntu-server.iso"),
    ];
    let results = build_ember_keyword_built(&blobs, &["ubuntu".to_string()], None).results;
    assert_eq!(results.len(), 2, "two distinct files");
    let a = results
        .iter()
        .find(|r| r.file.hash == hex::encode(hash_a))
        .expect("file A present");
    assert_eq!(a.availability, 2, "two distinct publishers for file A");
    assert_eq!(a.result_origin, crate::search::merge::ORIGIN_EMBER);
    assert_eq!(a.file.size, 100);
    assert_eq!(a.file.extension, "iso");
    assert!(
        a.source_addresses.is_empty(),
        "keyword hits carry no sources"
    );
    // Only complete public shares are keyword-published, so each publisher
    // is a complete source. Zero here read as "none" to every consumer of
    // the field: the Min Complete filter dropped every Ember row, and
    // `sort_search_results` ranks it first and put them last.
    assert_eq!(
        a.file.complete_sources, 2,
        "each distinct publisher of a keyword record holds the whole file"
    );
    let b = results
        .iter()
        .find(|r| r.file.hash == hex::encode(hash_b))
        .expect("file B present");
    assert_eq!(b.availability, 1);
    assert_eq!(b.file.complete_sources, 1);
}

/// The probe is a disk read awaited from the network task, so what it selects
/// is the whole cost. Two properties: an already-probed file is never read
/// again — the durable "found nothing" marker is pointless otherwise — and one
/// tick cannot read more than [`MEDIA_PROBES_PER_TICK`] files however many are
/// due.
#[test]
fn a_media_probe_reads_each_file_once_and_only_a_slice_per_tick() {
    let due: Vec<([u8; 16], u64, String, [u8; 32], String)> = (0..20u8)
        .map(|i| {
            (
                [i; 16],
                1024,
                format!("f{i}.mp3"),
                [0u8; 32],
                format!("C:/Library/f{i}.mp3"),
            )
        })
        .collect();

    // Nothing probed yet: one tick takes its slice and no more.
    let first = files_needing_media_probe(&due, |_| Some(false), MEDIA_PROBES_PER_TICK);
    assert_eq!(first.len(), MEDIA_PROBES_PER_TICK);
    assert_eq!(first[0].0, [0u8; 16]);
    assert_eq!(first[0].1, "C:/Library/f0.mp3");

    // Everything probed — including the files that turned out to have no
    // media, which is most of a real library. Nothing may be read again.
    assert!(
        files_needing_media_probe(&due, |_| Some(true), MEDIA_PROBES_PER_TICK).is_empty(),
        "a probed file must never be read a second time"
    );

    // A hash known.met has never heard of is not 'unprobed': there would be
    // nowhere to record the answer, so reading the disk would repeat forever.
    assert!(
        files_needing_media_probe(&due, |_| None, MEDIA_PROBES_PER_TICK).is_empty(),
        "a hash with no known.met record must not be probed"
    );

    // A row with no path has nothing to read.
    let pathless: Vec<_> = due
        .iter()
        .cloned()
        .map(|(h, s, n, e, _)| (h, s, n, e, String::new()))
        .collect();
    assert!(files_needing_media_probe(&pathless, |_| Some(false), 8).is_empty());
}

/// What the search sends its responders. Pinned because the wiring sits in
/// `command.rs`, which has no tests of its own, and because dropping a field
/// here breaks filtering silently — the searcher still filters at emit, so the
/// results stay correct and only the recall win disappears.
#[test]
fn an_ember_keyword_search_sends_size_type_and_extension_but_not_availability() {
    let constraints = ember_keyword_constraints(
        Some("Video".to_string()),
        Some(1024),
        Some(4096),
        Some("mkv".to_string()),
    );
    assert_eq!(constraints.min_size, Some(1024));
    assert_eq!(constraints.max_size, Some(4096));
    assert_eq!(constraints.file_type.as_deref(), Some("Video"));
    assert_eq!(
        constraints.file_extension.as_deref(),
        Some("mkv"),
        "the extension is how Ember searches by extension without indexing one"
    );
    assert!(
        constraints.extra_keys.is_empty(),
        "surplus keyword hashes are added by build_find_value, not here"
    );

    // An unfiltered search must send nothing at all, so its payload stays
    // byte-identical to what a build predating the block produces.
    assert!(ember_keyword_constraints(None, None, None, None).is_empty());
}

/// A record's media has to reach the row, which is the entire user-visible
/// point of putting it on the wire. The record end is covered in
/// `publish.rs`; nothing asserted the two lines that carry it across, so
/// dropping them passed the whole suite while every Ember row went back to
/// showing empty Length, Bitrate and tag columns.
#[test]
fn ember_keyword_results_carry_the_publishers_media() {
    let sk_a = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]);
    let sk_b = ed25519_dalek::SigningKey::from_bytes(&[0x52; 32]);
    let with_media = [0xAAu8; 16];
    let without_media = [0xBBu8; 16];
    let media = crate::types::MediaMetadata {
        duration: Some(214),
        bitrate: Some(320),
        codec: Some("mp3".into()),
        artist: Some("Anne Müller".into()),
        album: Some("Heliopause".into()),
        title: Some("Drifting Circles".into()),
    };

    let kw_with_media = |sk: &ed25519_dalek::SigningKey, file_hash: [u8; 16]| {
        let rec = ember::dht::publish::SignedRecord::keyword_with_media(
            "heliopause",
            file_hash,
            [0u8; 32],
            9_000_000,
            "anne-muller-heliopause.mp3",
            Some(&media),
            sk,
        );
        let mut blob = rec.data.clone();
        blob.extend_from_slice(&rec.signature);
        blob
    };

    let blobs = vec![
        // The first publisher of this file has no media — a build predating
        // the block, which is what most of the network is.
        ember_kw_blob(
            &sk_a,
            "heliopause",
            with_media,
            9_000_000,
            "anne-muller-heliopause.mp3",
        ),
        kw_with_media(&sk_b, with_media),
        ember_kw_blob(
            &sk_a,
            "heliopause",
            without_media,
            1_000,
            "heliopause-notes.txt",
        ),
    ];
    let results =
        build_ember_keyword_built(&blobs, &["heliopause".to_string()], None).results;

    let row = results
        .iter()
        .find(|r| r.file.hash == hex::encode(with_media))
        .expect("the file two publishers named");
    assert_eq!(
        row.media.as_ref(),
        Some(&media),
        "one publisher carrying media has to fill the row, even when the first did not"
    );
    assert_eq!(row.availability, 2);

    let bare = results
        .iter()
        .find(|r| r.file.hash == hex::encode(without_media))
        .expect("the file nobody published media for");
    assert!(
        bare.media.is_none(),
        "a record with no media block must not invent one"
    );
}

#[test]
fn ember_keyword_results_multi_word_and_filter() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let hash_a = [0x11u8; 16];
    let hash_b = [0x22u8; 16];
    // DHT lookup key is the longest query term. "ubuntuiso" is primary;
    // records are stored under it. Only file A's name also contains
    // "server".
    let blobs = vec![
        ember_kw_blob(&sk, "ubuntuiso", hash_a, 1, "ubuntuiso server amd64"),
        ember_kw_blob(&sk, "ubuntuiso", hash_b, 1, "ubuntuiso desktop amd64"),
    ];
    let results = build_ember_keyword_built(
        &blobs,
        &["ubuntuiso".to_string(), "server".to_string()],
        None,
    )
    .results;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].file.hash, hex::encode(hash_a));
}

#[test]
fn ember_keyword_results_accept_the_key_the_lookup_actually_walked() {
    // Equal-length keywords are the case where an independently computed
    // "longest keyword" diverges from the searcher's choice, which drops
    // every hit. Both terms are six characters on purpose.
    let sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    let hash_a = [0x44u8; 16];
    let keywords = vec!["ubuntu".to_string(), "server".to_string()];

    let walked = ember::dht::search::compute_keyword_hashes(&keywords.join(" "))
        .first()
        .map(|(_, kw)| kw.clone())
        .expect("query yields a primary keyword");
    let blobs = vec![ember_kw_blob(
        &sk,
        &walked,
        hash_a,
        1,
        "ubuntu server amd64.iso",
    )];

    let results = build_ember_keyword_built(&blobs, &keywords, None).results;
    assert_eq!(
        results.len(),
        1,
        "record stored under the walked key must survive the filter"
    );
    assert_eq!(results[0].file.hash, hex::encode(hash_a));
}

#[test]
fn ember_keyword_results_honor_boolean_queries() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
    let hash_a = [0x55u8; 16];
    let hash_b = [0x66u8; 16];

    // Both records live under the "reloaded" key; only one file name also
    // mentions "matrix".
    let blobs = vec![
        ember_kw_blob(&sk, "reloaded", hash_a, 1, "the matrix reloaded.mkv"),
        ember_kw_blob(&sk, "reloaded", hash_b, 1, "reloaded documentary.mkv"),
    ];
    let keywords = vec!["matrix".to_string(), "reloaded".to_string()];

    // An OR query must keep the file that matches only one side. The flat
    // keyword AND would drop it.
    let or_expr = crate::search::query::parse("matrix OR reloaded")
        .expect("query parses to an expression");
    let or_results = build_ember_keyword_built(&blobs, &keywords, Some(&or_expr)).results;
    assert_eq!(or_results.len(), 2, "OR keeps both sides");

    // A NOT query must drop the excluded file even though the excluded
    // term never appears in the flattened positive keywords.
    let not_expr = crate::search::query::parse("reloaded -documentary").expect("query parses");
    let not_results =
        build_ember_keyword_built(&blobs, &["reloaded".to_string()], Some(&not_expr)).results;
    assert_eq!(not_results.len(), 1, "NOT excludes the negated match");
    assert_eq!(not_results[0].file.hash, hex::encode(hash_a));
}

#[test]
fn ember_keyword_results_ignore_source_and_garbage_blobs() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]);
    let hash_a = [0x33u8; 16];
    let source = ember::dht::publish::SignedRecord::source(
        hash_a,
        [0u8; 32],
        1,
        "ubuntu.iso",
        ember::dht::publish::SourceContact {
            ip: std::net::Ipv4Addr::new(1, 2, 3, 4),
            tcp_port: 4662,
            udp_port: 4672,
            flags: 0,
            noise_pub: [0u8; 32],
            ..Default::default()
        },
        &sk,
    );
    let mut source_blob = source.data.clone();
    source_blob.extend_from_slice(&source.signature);
    // A source record (wrong type) and an undersized garbage blob.
    let blobs = vec![source_blob, vec![0u8; 8]];
    let results = build_ember_keyword_built(&blobs, &["ubuntu".to_string()], None).results;
    assert!(
        results.is_empty(),
        "source records and garbage must not become keyword hits"
    );
}

/// A source record is self-signed by a key it carries, so one hostile
/// publisher used to be able to name the digest the transfer enforces at
/// completion — and a mismatch there finds no corrupt parts, so the whole
/// file is re-downloaded forever.
#[test]
fn one_ember_source_publisher_cannot_name_the_expected_digest() {
    let honest_a = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
    let honest_b = ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]);
    let attacker = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
    let file_hash = [0x77u8; 16];
    let honest_digest = [0x01u8; 32];
    let blobs = vec![
        ember_source_blob(&honest_a, file_hash, honest_digest, 4),
        ember_source_blob(&honest_b, file_hash, honest_digest, 5),
        // Parsed last, which is exactly what the old code believed.
        ember_source_blob(&attacker, file_hash, [0xFEu8; 32], 6),
    ];
    let mut diag = crate::types::EmberDiagnostics::default();
    let mut noise_keys = HashMap::new();
    let mut content_hashes = HashMap::new();
    let sources = parse_ember_source_records(
        &blobs,
        file_hash,
        None,
        &mut diag,
        &mut noise_keys,
        &HashSet::new(),
        &mut content_hashes,
    );
    assert_eq!(sources.len(), 3, "every contact stays connectable");
    assert_eq!(
        content_hashes.get(&file_hash).map(|pin| pin.digest),
        Some(honest_digest)
    );
    assert_eq!(
        content_hashes.get(&file_hash).map(|pin| pin.provenance),
        Some(EmberDigestProvenance::Corroborated(2)),
        "the pin records how many publishers stood behind it"
    );
}

#[test]
fn firewalled_source_records_do_not_cache_noise_keys() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
    let file_hash = [0x42u8; 16];
    let victim = Ipv4Addr::new(8, 8, 8, 8);
    let attacker_key = [0xAAu8; 32];
    let blob = ember_source_blob_contact(
        &sk,
        file_hash,
        [0u8; 32],
        ember::dht::publish::SourceContact {
            ip: victim,
            tcp_port: 4662,
            udp_port: 4672,
            flags: ember::SOURCE_FLAG_FIREWALLED,
            noise_pub: attacker_key,
            ..Default::default()
        },
    );
    let mut diag = crate::types::EmberDiagnostics::default();
    let mut noise_keys = HashMap::new();
    let mut content_hashes = HashMap::new();
    let sources = parse_ember_source_records(
        &[blob],
        file_hash,
        None,
        &mut diag,
        &mut noise_keys,
        &HashSet::new(),
        &mut content_hashes,
    );
    assert_eq!(sources.len(), 1);
    assert!(
        noise_keys.is_empty(),
        "unbound firewalled contacts must not pin Noise keys"
    );
}

#[test]
fn firewalled_source_records_preserve_callback_buddy() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
    let file_hash = [0x44u8; 16];
    let buddy = ember::dht::publish::SourceBuddy {
        ip: Ipv4Addr::new(203, 0, 113, 10),
        udp_port: 4672,
        noise_pub: [0xB1; 32],
        ed25519_pub: [0xB2; 32],
        endorsed_until: 4_000_000_000,
        endorsement: [0xB3; 64],
    };
    let blob = ember_source_blob_contact(
        &sk,
        file_hash,
        [0u8; 32],
        ember::dht::publish::SourceContact {
            ip: Ipv4Addr::new(10, 0, 0, 9),
            tcp_port: 4662,
            udp_port: 4672,
            flags: ember::SOURCE_FLAG_FIREWALLED,
            noise_pub: [0x33; 32],
            user_hash: Some([0xCCu8; 16]),
            buddy: Some(buddy),
            callback_token: Some([0xDDu8; 16]),
        },
    );
    let mut diag = crate::types::EmberDiagnostics::default();
    let mut noise_keys = HashMap::new();
    let mut content_hashes = HashMap::new();
    let sources = parse_ember_source_records(
        &[blob],
        file_hash,
        None,
        &mut diag,
        &mut noise_keys,
        &HashSet::new(),
        &mut content_hashes,
    );
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].buddy, Some(buddy));
    assert_eq!(sources[0].user_hash, Some([0xCCu8; 16]));
    assert_eq!(sources[0].callback_token, Some([0xDDu8; 16]));
    assert_ne!(sources[0].publisher_id, [0u8; 16]);
    assert!(
        noise_keys.is_empty(),
        "firewalled buddy contacts must not pin Noise keys either"
    );
}

#[test]
fn highid_source_records_cache_bound_noise_keys() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]);
    let file_hash = [0x43u8; 16];
    let ip = Ipv4Addr::new(8, 8, 4, 4);
    let key = [0xBBu8; 32];
    let blob = ember_source_blob_contact(
        &sk,
        file_hash,
        [0u8; 32],
        ember::dht::publish::SourceContact {
            ip,
            tcp_port: 4662,
            udp_port: 4672,
            flags: 0,
            noise_pub: key,
            ..Default::default()
        },
    );
    let mut diag = crate::types::EmberDiagnostics::default();
    let mut noise_keys = HashMap::new();
    let mut content_hashes = HashMap::new();
    parse_ember_source_records(
        &[blob],
        file_hash,
        None,
        &mut diag,
        &mut noise_keys,
        &HashSet::new(),
        &mut content_hashes,
    );
    assert_eq!(lookup_ember_noise_key(&noise_keys, ip, 4672), Some(key));
}

/// The digest seeded at `StartDownload` from the UI / known.met / a hash we
/// computed ourselves outranks the DHT however many publishers disagree.
#[test]
fn ember_source_records_never_overwrite_a_trusted_digest() {
    let sk1 = ed25519_dalek::SigningKey::from_bytes(&[14u8; 32]);
    let sk2 = ed25519_dalek::SigningKey::from_bytes(&[15u8; 32]);
    let file_hash = [0x88u8; 16];
    let trusted = [0x02u8; 32];
    let blobs = vec![
        ember_source_blob(&sk1, file_hash, [0xFEu8; 32], 1),
        ember_source_blob(&sk2, file_hash, [0xFEu8; 32], 2),
    ];
    let mut diag = crate::types::EmberDiagnostics::default();
    let mut noise_keys = HashMap::new();
    let mut content_hashes: HashMap<[u8; 16], EmberDigestPin> = HashMap::from([(
        file_hash,
        EmberDigestPin {
            digest: trusted,
            provenance: EmberDigestProvenance::Local,
        },
    )]);
    parse_ember_source_records(
        &blobs,
        file_hash,
        None,
        &mut diag,
        &mut noise_keys,
        &HashSet::new(),
        &mut content_hashes,
    );
    assert_eq!(
        content_hashes.get(&file_hash).map(|pin| pin.digest),
        Some(trusted)
    );
}

/// Which digest a transfer enforces has to be decided by evidence, not by
/// which walk happened to answer first.
///
/// Two publishers agreeing inside one incremental `FIND_VALUE` page is
/// enough to corroborate *within that page*, so a partial answer could pin
/// a digest the finished walk went on to contradict — and, once pinned,
/// nothing could correct it. Worse, the digest on the row the user actually
/// clicked lost to whatever that page had already seeded, so an explicit
/// choice was overridden by a guess.
#[test]
fn a_better_supported_ember_digest_supersedes_a_weaker_pin() {
    let mut pins: HashMap<[u8; 16], EmberDigestPin> = HashMap::new();
    let file = [0x5Au8; 16];
    let early = [0xAAu8; 32];
    let plurality = [0xBBu8; 32];
    let clicked = [0xCCu8; 32];
    let hashed_here = [0xDDu8; 32];

    seed_ember_content_hash(
        &mut pins,
        file,
        early,
        EmberDigestProvenance::Corroborated(2),
    );
    assert_eq!(pins[&file].digest, early);

    // An equal number of publishers must not flip a live pin, or two rival
    // pairs would fight over it for the length of the download.
    seed_ember_content_hash(
        &mut pins,
        file,
        plurality,
        EmberDigestProvenance::Corroborated(2),
    );
    assert_eq!(pins[&file].digest, early, "equal evidence keeps the incumbent");

    seed_ember_content_hash(
        &mut pins,
        file,
        plurality,
        EmberDigestProvenance::Corroborated(3),
    );
    assert_eq!(
        pins[&file].digest, plurality,
        "a larger plurality is what the completed walk found"
    );

    seed_ember_content_hash(&mut pins, file, clicked, EmberDigestProvenance::UserSelected);
    assert_eq!(
        pins[&file].digest, clicked,
        "the row the user clicked outranks any DHT plurality"
    );

    seed_ember_content_hash(&mut pins, file, hashed_here, EmberDigestProvenance::Local);
    assert_eq!(
        pins[&file].digest, hashed_here,
        "bytes hashed on this machine outrank everything remote"
    );

    seed_ember_content_hash(
        &mut pins,
        file,
        plurality,
        EmberDigestProvenance::Corroborated(9),
    );
    assert_eq!(
        pins[&file].digest, hashed_here,
        "and no amount of remote agreement displaces a local hash"
    );

    // "No claim" is not a claim.
    seed_ember_content_hash(&mut pins, [0x11u8; 16], [0u8; 32], EmberDigestProvenance::Local);
    assert!(!pins.contains_key(&[0x11u8; 16]));
}

#[test]
fn record_known_ember_peer_returns_true_for_new_entries() {
    let mut map = HashMap::new();
    let ip = Ipv4Addr::new(1, 2, 3, 4);
    assert!(record_known_ember_peer(&mut map, ip, 4662));
    assert_eq!(map.len(), 1);
}

fn udp_peer(last: u8) -> SocketAddr {
    SocketAddr::from(([80, 2, 2, last], 4672))
}

/// The budget a peer gets before its UDP exchanges are refused. Answering
/// one costs a payload build and a send, so an unmetered peer could make
/// us do that work as fast as it can ask.
#[test]
fn udp_epx_allows_a_peers_budget_then_refuses() {
    let mut map = HashMap::new();
    let addr = udp_peer(1);

    for attempt in 1..=ember::MAX_EPX_PACKETS_PER_CONNECTION {
        assert!(
            check_and_record_udp_epx_rate(&mut map, addr),
            "request {attempt} is within budget"
        );
    }
    assert!(
        !check_and_record_udp_epx_rate(&mut map, addr),
        "one past the budget must be refused"
    );
}

/// Budgets are per address, so a noisy peer cannot mute a quiet one.
#[test]
fn udp_epx_budgets_are_not_shared_between_peers() {
    let mut map = HashMap::new();
    let noisy = udp_peer(2);
    for _ in 0..=ember::MAX_EPX_PACKETS_PER_CONNECTION {
        check_and_record_udp_epx_rate(&mut map, noisy);
    }
    assert!(!check_and_record_udp_epx_rate(&mut map, noisy));

    assert!(
        check_and_record_udp_epx_rate(&mut map, udp_peer(3)),
        "a different peer starts with its own budget"
    );
}

/// The window rolls: a peer that waited out its window is served again,
/// which is what keeps the limit from permanently muting a legitimate
/// peer whose re-send cadence happens to line up with it.
#[test]
fn udp_epx_budget_refills_after_the_window() {
    let mut map = HashMap::new();
    let addr = udp_peer(4);
    for _ in 0..ember::MAX_EPX_PACKETS_PER_CONNECTION {
        assert!(check_and_record_udp_epx_rate(&mut map, addr));
    }
    assert!(!check_and_record_udp_epx_rate(&mut map, addr));

    // Back-date the window rather than sleeping through five minutes.
    let stale = std::time::Instant::now()
        .checked_sub(EPX_UDP_RATE_WINDOW)
        .expect("clock far enough from boot to back-date");
    map.get_mut(&addr).unwrap().1 = stale;

    assert!(
        check_and_record_udp_epx_rate(&mut map, addr),
        "the window has rolled, so the peer is served again"
    );
    assert_eq!(
        map.get(&addr).unwrap().0,
        1,
        "and its budget starts over rather than resuming mid-window"
    );
}

/// The map is capped so a flood of distinct addresses cannot grow it
/// without bound. The cost, worth stating explicitly: eviction is by age,
/// so a large enough flood can push out a real peer's counter and hand it
/// a fresh budget. Memory is the bound being defended here, not fairness.
#[test]
fn udp_epx_rate_map_is_bounded_by_evicting_the_oldest() {
    let mut map = HashMap::new();
    let first = SocketAddr::from(([10, 0, 0, 1], 4672));
    assert!(check_and_record_udp_epx_rate(&mut map, first));

    for i in 0..MAX_EMBER_UDP_EPX_RATE_ENTRIES {
        let i = i as u32;
        let addr = SocketAddr::from((
            [11, (i >> 16) as u8, (i >> 8) as u8, (i & 0xFF) as u8],
            4672,
        ));
        check_and_record_udp_epx_rate(&mut map, addr);
    }

    assert!(
        map.len() <= MAX_EMBER_UDP_EPX_RATE_ENTRIES,
        "the map must stay within its cap"
    );
    assert!(
        !map.contains_key(&first),
        "the oldest entry is the one given up"
    );
}

#[test]
fn record_known_ember_peer_refreshes_existing_timestamp() {
    let mut map = HashMap::new();
    let ip = Ipv4Addr::new(1, 2, 3, 4);
    assert!(record_known_ember_peer(&mut map, ip, 4662));
    let first_ts = *map.get(&(ip, 4662)).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    // Re-recording the same address must NOT report it as new (so we
    // don't spuriously dirty the EPX payload), but it MUST move the
    // timestamp forward so the pruner doesn't evict an active peer.
    assert!(!record_known_ember_peer(&mut map, ip, 4662));
    let second_ts = *map.get(&(ip, 4662)).unwrap();
    assert!(second_ts > first_ts);
    assert_eq!(map.len(), 1);
}

#[test]
fn record_known_ember_peer_evicts_oldest_at_capacity() {
    let mut map = HashMap::new();
    // Fill exactly to the cap with sequentially-aged entries — the
    // first insert is the oldest by timestamp. Use the high two bytes
    // of the IPv4 address so we get enough unique addresses to
    // exceed `MAX_KNOWN_EMBER_PEERS` (500) without overflowing u8.
    for i in 0..MAX_KNOWN_EMBER_PEERS {
        let i = i as u16;
        let ip = Ipv4Addr::new(10, 0, (i >> 8) as u8, (i & 0xFF) as u8);
        assert!(record_known_ember_peer(&mut map, ip, 4662));
        std::thread::sleep(std::time::Duration::from_micros(50));
    }
    let oldest = (Ipv4Addr::new(10, 0, 0, 0), 4662u16);
    assert!(map.contains_key(&oldest));
    assert_eq!(map.len(), MAX_KNOWN_EMBER_PEERS);

    // Inserting one more brand-new address must evict the oldest
    // entry, not the new one or anything in between.
    let newcomer = Ipv4Addr::new(11, 0, 0, 1);
    assert!(record_known_ember_peer(&mut map, newcomer, 4662));
    assert_eq!(map.len(), MAX_KNOWN_EMBER_PEERS);
    assert!(!map.contains_key(&oldest));
    assert!(map.contains_key(&(newcomer, 4662)));
}

#[test]
fn record_ember_noise_key_pins_first_seen_against_poison() {
    let mut map = HashMap::new();
    let ip = Ipv4Addr::new(1, 2, 3, 4);
    let port = 4662u16;

    let key1 = [0xAAu8; 32];
    let key2 = [0xBBu8; 32];

    // First insert: nothing previous to report.
    assert_eq!(record_ember_noise_key(&mut map, ip, port, key1), None);
    assert_eq!(map[&(ip, port)].0, key1);

    // Same key → refresh only, no conflict reported.
    assert_eq!(record_ember_noise_key(&mut map, ip, port, key1), None);
    assert_eq!(map[&(ip, port)].0, key1);

    // Different key while pin is live → reject poison / premature
    // rotation; keep first-seen key and report the pinned value.
    assert_eq!(record_ember_noise_key(&mut map, ip, port, key2), Some(key1));
    assert_eq!(map[&(ip, port)].0, key1);
}

#[test]
fn cache_bound_ember_noise_key_rejects_bogus_and_zero_key() {
    let mut map = HashMap::new();
    let key = [0xAAu8; 32];
    assert!(cache_bound_ember_noise_key(
        &mut map,
        Ipv4Addr::new(203, 0, 113, 1),
        4672,
        key,
        true
    )
    .is_none());
    assert!(
        cache_bound_ember_noise_key(&mut map, Ipv4Addr::new(8, 8, 8, 8), 0, key, true)
            .is_none()
    );
    assert!(cache_bound_ember_noise_key(
        &mut map,
        Ipv4Addr::new(8, 8, 8, 8),
        4672,
        [0u8; 32],
        true
    )
    .is_none());
    assert!(map.is_empty());
    assert!(cache_bound_ember_noise_key(
        &mut map,
        Ipv4Addr::new(8, 8, 8, 8),
        4672,
        key,
        true
    )
    .is_none());
    assert_eq!(
        lookup_ember_noise_key(&map, Ipv4Addr::new(8, 8, 8, 8), 4672),
        Some(key)
    );
}

/// The pin defends a peer we already reach from an unauthenticated KAD tag
/// redirecting our dials. Applied to an address we have never reached it
/// did the opposite: a wrong first sighting is exactly why we cannot reach
/// it, and holding it kept the IK dial broken for a day while the XX pass
/// skipped the address for having a "known" key.
#[test]
fn a_key_we_have_never_reached_is_replaced_by_a_later_advert() {
    let mut map = HashMap::new();
    let ip = Ipv4Addr::new(80, 1, 2, 3);
    let stale = [0x11u8; 32];
    let real = [0x22u8; 32];

    assert!(cache_bound_ember_noise_key(&mut map, ip, 4672, stale, false).is_none());
    assert!(
        cache_bound_ember_noise_key(&mut map, ip, 4672, real, false).is_none(),
        "no established contact means nothing worth pinning"
    );
    assert_eq!(lookup_ember_noise_key(&map, ip, 4672), Some(real));
}

/// Once the address is a live contact, its key is the one that demonstrably
/// works and a conflicting advert is poison.
#[test]
fn a_key_that_reaches_a_live_contact_is_pinned_against_conflicts() {
    let mut map = HashMap::new();
    let ip = Ipv4Addr::new(80, 1, 2, 4);
    let working = [0x33u8; 32];
    let poison = [0x44u8; 32];

    assert!(cache_bound_ember_noise_key(&mut map, ip, 4672, working, true).is_none());
    assert_eq!(
        cache_bound_ember_noise_key(&mut map, ip, 4672, poison, true),
        Some(working),
        "the conflict is reported and refused"
    );
    assert_eq!(lookup_ember_noise_key(&map, ip, 4672), Some(working));
}

/// Ten minutes is right for a node that cannot reach anyone, but it was
/// also the wait after the very first miss — and this key is the only
/// cold-join path there is.
#[test]
fn the_rendezvous_retry_backs_off_from_short_to_the_steady_interval() {
    assert_eq!(
        ember_rendezvous_retry_secs(0),
        EMBER_RENDEZVOUS_LOOKUP_INTERVAL_SECS,
        "a lookup that found peers is in no hurry"
    );
    assert_eq!(
        ember_rendezvous_retry_secs(1),
        EMBER_RENDEZVOUS_FIRST_RETRY_SECS
    );
    assert!(ember_rendezvous_retry_secs(2) > ember_rendezvous_retry_secs(1));
    assert!(ember_rendezvous_retry_secs(3) > ember_rendezvous_retry_secs(2));
    for streak in [8u32, 64, u32::MAX] {
        assert_eq!(
            ember_rendezvous_retry_secs(streak),
            EMBER_RENDEZVOUS_LOOKUP_INTERVAL_SECS,
            "a stuck node settles at the steady interval, never past it"
        );
    }
}

#[test]
fn rendezvous_conversion_counts_live_table_and_session_contacts() {
    let a = (Ipv4Addr::new(1, 2, 3, 4), 4672);
    let b = (Ipv4Addr::new(5, 6, 7, 8), 4672);
    let listed = [a, b];
    let mut established = HashSet::new();
    let mut session = HashSet::new();
    assert_eq!(
        ember_rendezvous_converted_among(&listed, &established, &session),
        0,
        "listed peers that are not contacts have not converted"
    );
    established.insert(a);
    assert_eq!(
        ember_rendezvous_converted_among(&listed, &established, &session),
        1
    );
    session.insert(b);
    assert_eq!(
        ember_rendezvous_converted_among(&listed, &established, &session),
        2
    );
}

#[test]
fn the_rendezvous_empty_streak_follows_conversion_not_listing() {
    // Cold join: nobody converted → streak 0→1, first retry at 60s.
    let after_miss = ember_rendezvous_empty_streak_after(0, 0);
    assert_eq!(after_miss, 1);
    assert_eq!(
        ember_rendezvous_retry_secs(after_miss),
        EMBER_RENDEZVOUS_FIRST_RETRY_SECS
    );
    // A later lookup that finds someone already in the table resets.
    let after_hit = ember_rendezvous_empty_streak_after(after_miss, 1);
    assert_eq!(after_hit, 0);
    assert_eq!(
        ember_rendezvous_retry_secs(after_hit),
        EMBER_RENDEZVOUS_LOOKUP_INTERVAL_SECS
    );
    assert_eq!(ember_rendezvous_empty_streak_after(1, 0), 2);
    assert_eq!(ember_rendezvous_empty_streak_after(3, 0), 4);
    assert_eq!(ember_rendezvous_empty_streak_after(5, 2), 0);
}

#[test]
fn stun_may_replace_a_kad_vote_but_not_a_live_highid() {
    let stun = Ipv4Addr::new(8, 8, 8, 8);
    let kad = Ipv4Addr::new(4, 4, 4, 4);
    let highid = Ipv4Addr::new(1, 1, 1, 1);
    assert!(should_adopt_stun_external_ip(None, stun, None));
    assert!(should_adopt_stun_external_ip(Some(kad), stun, None));
    assert!(
        !should_adopt_stun_external_ip(Some(highid), stun, Some(highid)),
        "a TCP HighID must not be displaced by a UDP STUN mapping"
    );
    assert!(!should_adopt_stun_external_ip(Some(stun), stun, None));
    assert!(!should_adopt_stun_external_ip(
        None,
        Ipv4Addr::new(203, 0, 113, 1),
        None
    ));
    assert!(
        should_adopt_stun_external_ip(Some(kad), stun, Some(highid)),
        "HighID that has not yet been applied must not block STUN from replacing KAD"
    );
}

#[test]
fn record_ember_noise_key_accepts_new_key_after_ttl() {
    let mut map = HashMap::new();
    let ip = Ipv4Addr::new(1, 2, 3, 4);
    let port = 4662u16;
    let key1 = [0xAAu8; 32];
    let key2 = [0xBBu8; 32];

    // Anchor both "then" and "now" to a synthetic timeline so we never
    // depend on Instant::checked_sub against wall-clock boot age.
    let then = std::time::Instant::now();
    let now = then + KNOWN_EMBER_PEER_TTL + std::time::Duration::from_secs(1);
    assert_eq!(
        record_ember_noise_key_at(&mut map, ip, port, key1, then),
        None
    );
    assert_eq!(
        record_ember_noise_key_at(&mut map, ip, port, key2, now),
        None
    );
    assert_eq!(map[&(ip, port)].0, key2);
}

#[test]
fn kad_bridge_candidates_skips_attempted_and_prefers_freshest() {
    let mut map: HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)> = HashMap::new();
    // Insert three peers oldest-first so their timestamps strictly
    // increase; peer C is the freshest.
    let a = (Ipv4Addr::new(10, 0, 0, 1), 4772u16);
    let b = (Ipv4Addr::new(10, 0, 0, 2), 4772u16);
    let c = (Ipv4Addr::new(10, 0, 0, 3), 4772u16);
    record_ember_noise_key(&mut map, a.0, a.1, [0xAA; 32]);
    std::thread::sleep(std::time::Duration::from_micros(50));
    record_ember_noise_key(&mut map, b.0, b.1, [0xBB; 32]);
    std::thread::sleep(std::time::Duration::from_micros(50));
    record_ember_noise_key(&mut map, c.0, c.1, [0xCC; 32]);

    // Nothing attempted yet → freshest-first, capped at `max`.
    let empty: HashMap<(Ipv4Addr, u16), (std::time::Instant, u32)> = HashMap::new();
    let picked = kad_bridge_candidates(&map, &empty, 2, false);
    assert_eq!(picked.len(), 2);
    assert_eq!((picked[0].0, picked[0].1), c); // freshest first
    assert_eq!(picked[0].2, [0xCC; 32]);
    assert_eq!((picked[1].0, picked[1].1), b);

    // Mark C attempted → it drops out, leaving B then A.
    let mut attempted = HashMap::new();
    attempted.insert(c, (std::time::Instant::now(), 1u32));
    let picked = kad_bridge_candidates(&map, &attempted, 8, false);
    assert_eq!(picked.len(), 2);
    assert_eq!((picked[0].0, picked[0].1), b);
    assert_eq!((picked[1].0, picked[1].1), a);

    // max == 0 → no work.
    assert!(kad_bridge_candidates(&map, &empty, 0, false).is_empty());
}

#[test]
fn kad_bridge_candidates_skip_documentation_addresses() {
    let mut map: HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)> = HashMap::new();
    let docs = Ipv4Addr::new(203, 0, 113, 50);
    let ok = Ipv4Addr::new(8, 8, 8, 8);
    record_ember_noise_key(&mut map, docs, 4672, [0xAA; 32]);
    record_ember_noise_key(&mut map, ok, 4672, [0xBB; 32]);
    let empty: HashMap<(Ipv4Addr, u16), (std::time::Instant, u32)> = HashMap::new();
    let picked = kad_bridge_candidates(&map, &empty, 8, false);
    assert_eq!(picked.len(), 1);
    assert_eq!(picked[0].0, ok);
}

/// A peer we already hold a Noise key for must go through the 1-RTT IK
/// path. Letting it into the XX pass too would spend the tick's budget
/// dialing the same peer twice, once the slow way.
#[test]
fn xx_bridge_skips_peers_whose_noise_key_is_known() {
    let mut keyless: HashMap<(Ipv4Addr, u16), std::time::Instant> = HashMap::new();
    let mut keys: HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)> = HashMap::new();

    let keyed = (Ipv4Addr::new(10, 0, 0, 1), 4672u16);
    let bare = (Ipv4Addr::new(10, 0, 0, 2), 4672u16);
    assert!(record_ember_keyless_peer(&mut keyless, keyed.0, keyed.1));
    assert!(record_ember_keyless_peer(&mut keyless, bare.0, bare.1));
    record_ember_noise_key(&mut keys, keyed.0, keyed.1, [0xAA; 32]);

    let picked = xx_bridge_candidates(&keyless, &keys, &HashMap::new(), 8, false);
    assert_eq!(picked, vec![bare]);
}

/// The bridge marks every peer it dials as attempted so it advances
/// through the cache; the XX pass has to honour that set too, or an
/// unreachable peer gets re-pinged on every maintenance tick forever.
#[test]
fn xx_bridge_honours_the_attempted_set_and_its_budget() {
    let mut keyless: HashMap<(Ipv4Addr, u16), std::time::Instant> = HashMap::new();
    let keys: HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)> = HashMap::new();

    let a = (Ipv4Addr::new(10, 0, 0, 1), 4672u16);
    let b = (Ipv4Addr::new(10, 0, 0, 2), 4672u16);
    record_ember_keyless_peer(&mut keyless, a.0, a.1);
    std::thread::sleep(std::time::Duration::from_micros(50));
    record_ember_keyless_peer(&mut keyless, b.0, b.1);

    // Freshest first, and the budget caps the batch.
    assert_eq!(
        xx_bridge_candidates(&keyless, &keys, &HashMap::new(), 1, false),
        vec![b]
    );

    let mut attempted = HashMap::new();
    attempted.insert(b, (std::time::Instant::now(), 1u32));
    assert_eq!(
        xx_bridge_candidates(&keyless, &keys, &attempted, 8, false),
        vec![a]
    );

    // A spent budget means no work, which is how the IK pass reserves it.
    assert!(xx_bridge_candidates(&keyless, &keys, &HashMap::new(), 0, false).is_empty());
}

/// One lost ping must not be final. The discovery caches refresh a peer's
/// timestamp every time it is re-observed, so an attempt recorded forever
/// would leave a node re-learning exactly the peers it needs while never
/// being allowed to dial them again.
#[test]
fn a_bridge_peer_becomes_a_candidate_again_after_the_retry_window() {
    let mut keys: HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)> = HashMap::new();
    let mut keyless: HashMap<(Ipv4Addr, u16), std::time::Instant> = HashMap::new();
    let peer = (Ipv4Addr::new(10, 0, 0, 7), 4672u16);
    record_ember_noise_key(&mut keys, peer.0, peer.1, [0xDD; 32]);
    record_ember_keyless_peer(&mut keyless, peer.0, peer.1);

    let attempt_at = std::time::Instant::now();
    let mut attempted = HashMap::new();
    attempted.insert(peer, (attempt_at, 1u32));

    // Just after the attempt the bridge moves on to other peers.
    let soon = attempt_at + std::time::Duration::from_secs(30);
    assert!(kad_bridge_candidates_at(&keys, &attempted, 8, soon, false).is_empty());

    // Past the window it is eligible again.
    let later = attempt_at + EMBER_BRIDGE_RETRY_FIRST;
    let picked = kad_bridge_candidates_at(&keys, &attempted, 8, later, false);
    assert_eq!(picked.len(), 1);
    assert_eq!((picked[0].0, picked[0].1), peer);

    // The XX pass honours the same window (with no Noise key known).
    let no_keys: HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)> = HashMap::new();
    assert!(
        xx_bridge_candidates_at(&keyless, &no_keys, &attempted, 8, soon, false).is_empty()
    );
    assert_eq!(
        xx_bridge_candidates_at(&keyless, &no_keys, &attempted, 8, later, false),
        vec![peer]
    );
}

/// The first retry has to be quick — the causes it exists for (a dropped
/// datagram, a peer that blinked, a NAT that needed a punch) clear in
/// seconds. A peer that keeps ignoring us must still settle at the old flat
/// rate rather than being probed forever.
#[test]
fn bridge_retry_backs_off_from_one_maintenance_tick_to_the_old_ceiling() {
    assert_eq!(bridge_retry_after(1, false), EMBER_BRIDGE_RETRY_FIRST);
    assert_eq!(bridge_retry_after(2, false), EMBER_BRIDGE_RETRY_FIRST * 2);
    assert_eq!(bridge_retry_after(3, false), EMBER_BRIDGE_RETRY_FIRST * 4);
    assert_eq!(bridge_retry_after(4, false), EMBER_BRIDGE_RETRY_MAX);
    assert_eq!(bridge_retry_after(50, false), EMBER_BRIDGE_RETRY_MAX);
    // Saturating rather than shifting past the width of the counter.
    assert_eq!(bridge_retry_after(u32::MAX, false), EMBER_BRIDGE_RETRY_MAX);
    // A peer with no recorded attempt is due immediately.
    assert_eq!(bridge_retry_after(0, false), EMBER_BRIDGE_RETRY_FIRST);
}

/// While the table is too thin to run a lookup on, the backoff flattens to
/// its first step. The curve is right for a healthy node deciding how much
/// to keep spending on an address that will not answer; it is wrong when
/// those addresses are the entire join, because five minutes is longer than
/// many sessions and a friend who dropped one datagram gets no second
/// chance inside a visit.
#[test]
fn a_starved_table_does_not_let_the_bridge_back_off() {
    for attempts in [0u32, 1, 2, 3, 4, 50, u32::MAX] {
        assert_eq!(
            bridge_retry_after(attempts, true),
            EMBER_BRIDGE_RETRY_FIRST,
            "a starved node retries every tick, whatever the attempt count"
        );
    }

    // And it is the maintenance tick, not something faster: the bridge is
    // driven by that timer, so this cannot become a busy loop.
    assert_eq!(EMBER_BRIDGE_RETRY_FIRST, EMBER_MAINT_INTERVAL);

    // The same peer, same history, is due while starved and not otherwise.
    let mut keys: HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)> = HashMap::new();
    let peer = (Ipv4Addr::new(8, 8, 8, 8), 4672u16);
    record_ember_noise_key(&mut keys, peer.0, peer.1, [0x11; 32]);
    let at = std::time::Instant::now();
    let mut attempted = HashMap::new();
    // Four misses: settled at the five-minute ceiling on a healthy table.
    attempted.insert(peer, (at, 4u32));
    let one_tick = at + EMBER_BRIDGE_RETRY_FIRST;

    assert!(
        kad_bridge_candidates_at(&keys, &attempted, 8, one_tick, false).is_empty(),
        "a healthy table still lets a dead address rest"
    );
    assert_eq!(
        kad_bridge_candidates_at(&keys, &attempted, 8, one_tick, true).len(),
        1,
        "a starved one tries again on the next tick"
    );
}

/// Flattening the backoff made every address due on every tick, and with
/// freshness as the only key the same freshest few — re-observed by each
/// KAD lookup whether or not they ever answered — took the whole budget
/// every time. An address that has never been asked has to come ahead of
/// one that has ignored us, however recently the latter was seen.
#[test]
fn a_starved_bridge_tries_untested_addresses_before_ones_that_kept_ignoring_it() {
    let mut keys: HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)> = HashMap::new();
    let mut keyless: HashMap<(Ipv4Addr, u16), std::time::Instant> = HashMap::new();
    let ignored_fresh = (Ipv4Addr::new(8, 8, 8, 1), 4672u16);
    let untried_old = (Ipv4Addr::new(8, 8, 8, 2), 4672u16);
    let untried_fresh = (Ipv4Addr::new(8, 8, 8, 3), 4672u16);
    let once_missed = (Ipv4Addr::new(8, 8, 8, 4), 4672u16);
    // Oldest observation first so the timestamps strictly increase.
    for peer in [untried_old, once_missed, untried_fresh, ignored_fresh] {
        record_ember_noise_key(&mut keys, peer.0, peer.1, [0x22; 32]);
        record_ember_keyless_peer(&mut keyless, peer.0, peer.1);
        std::thread::sleep(std::time::Duration::from_micros(50));
    }
    let at = std::time::Instant::now();
    let mut attempted = HashMap::new();
    attempted.insert(ignored_fresh, (at, 3u32));
    attempted.insert(once_missed, (at, 1u32));
    let one_tick = at + EMBER_BRIDGE_RETRY_FIRST;

    let picked: Vec<_> = kad_bridge_candidates_at(&keys, &attempted, 8, one_tick, true)
        .into_iter()
        .map(|(ip, port, _)| (ip, port))
        .collect();
    assert_eq!(
        picked,
        vec![untried_fresh, untried_old, once_missed, ignored_fresh],
        "never-asked first (freshest of those ahead), then by how often each has ignored us"
    );
    // A budget of two therefore reaches both untried addresses, where the
    // old order spent one of them re-dialling the address with three misses.
    let two: Vec<_> = kad_bridge_candidates_at(&keys, &attempted, 2, one_tick, true)
        .into_iter()
        .map(|(ip, port, _)| (ip, port))
        .collect();
    assert_eq!(two, vec![untried_fresh, untried_old]);

    // The XX side ranks the same way.
    let no_keys: HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)> = HashMap::new();
    assert_eq!(
        xx_bridge_candidates_at(&keyless, &no_keys, &attempted, 8, one_tick, true),
        vec![untried_fresh, untried_old, once_missed, ignored_fresh]
    );
}

/// The IK pass ran first and left the XX pass its remainder. While starved,
/// a key cache with more due addresses than the budget — the usual state of
/// a KAD-fed cache, most of it stale source records — left nothing over, so
/// the keyless peers, which are live sessions and the likeliest to answer,
/// were never dialled at all.
#[test]
fn the_xx_bridge_pass_keeps_a_share_of_the_budget_while_there_is_anyone_to_spend_it_on() {
    // A quarter, floored at one so the four-ping fast pass still reaches it.
    assert_eq!(
        xx_bridge_reserve(EMBER_KAD_BRIDGE_MAX_PINGS, true),
        EMBER_KAD_BRIDGE_MAX_PINGS / 4
    );
    assert_eq!(xx_bridge_reserve(EMBER_BRIDGE_FAST_MAX_PINGS, true), 1);
    assert_eq!(xx_bridge_reserve(1, true), 1);
    // Never more than the pass itself, and nothing at all when the pass is
    // empty or there is no keyless peer to spend it on.
    assert_eq!(xx_bridge_reserve(0, true), 0);
    assert_eq!(xx_bridge_reserve(EMBER_KAD_BRIDGE_MAX_PINGS, false), 0);
    assert!(xx_bridge_reserve(EMBER_KAD_BRIDGE_MAX_PINGS, true) < EMBER_KAD_BRIDGE_MAX_PINGS);
}

/// Each unanswered ping must lengthen the next wait. Overwriting the entry
/// instead of incrementing would pin every peer at the first interval and
/// re-probe a dead one every maintenance tick forever.
#[test]
fn repeated_bridge_failures_lengthen_the_window() {
    let mut keys: HashMap<(Ipv4Addr, u16), ([u8; 32], std::time::Instant)> = HashMap::new();
    let peer = (Ipv4Addr::new(10, 0, 0, 9), 4672u16);
    record_ember_noise_key(&mut keys, peer.0, peer.1, [0xEE; 32]);

    let at = std::time::Instant::now();
    let mut attempted = HashMap::new();
    attempted.insert(peer, (at, 3u32));

    // Two doublings in: one tick is no longer enough.
    assert!(
        kad_bridge_candidates_at(&keys, &attempted, 8, at + EMBER_BRIDGE_RETRY_FIRST, false)
            .is_empty()
    );
    assert_eq!(
        kad_bridge_candidates_at(
            &keys,
            &attempted,
            8,
            at + EMBER_BRIDGE_RETRY_FIRST * 4,
            false
        )
        .len(),
        1
    );
}

/// Ember rides the shared KAD UDP socket, so a peer that advertised no UDP
/// port has no address the bridge could dial. Recording it under port 0
/// would put an undialable entry in the cache and waste a ping budget slot.
#[test]
fn a_peer_without_a_udp_port_is_not_a_bridge_candidate() {
    let mut keyless: HashMap<(Ipv4Addr, u16), std::time::Instant> = HashMap::new();
    assert!(!record_ember_keyless_peer(
        &mut keyless,
        Ipv4Addr::new(10, 0, 0, 1),
        0
    ));
    assert!(keyless.is_empty());
}

#[test]
fn session_dht_contacts_keep_lan_and_drop_bogus() {
    let mut map = HashMap::new();
    let lan = ember::dht::EmberContact {
        node_id: ember::dht::EmberNodeId([1u8; 16]),
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 4672),
        noise_pub: [2u8; 32],
        ed25519_pub: [3u8; 32],
        last_seen: 1,
        failed_queries: 0,
    };
    record_ember_session_dht_contact(&mut map, lan);
    assert_eq!(map.len(), 1);

    let loopback = ember::dht::EmberContact {
        node_id: ember::dht::EmberNodeId([4u8; 16]),
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4672),
        noise_pub: [5u8; 32],
        ed25519_pub: [6u8; 32],
        last_seen: 1,
        failed_queries: 0,
    };
    record_ember_session_dht_contact(&mut map, loopback);
    assert_eq!(map.len(), 1, "loopback is never a DHT contact");
}

/// A NAT remap records a second UDP port for the same host. A third
/// mapping must drop the oldest extra so the IP-filter exemption cannot
/// grow with every Hello UDP change.
#[test]
fn session_dht_contacts_keep_at_most_two_udp_ports_per_host() {
    let mut map = HashMap::new();
    let ip = Ipv4Addr::new(192, 168, 1, 10);
    for (i, port) in [4672u16, 4673, 4674].into_iter().enumerate() {
        record_ember_session_dht_contact(
            &mut map,
            ember::dht::EmberContact {
                node_id: ember::dht::EmberNodeId([i as u8 + 1; 16]),
                addr: SocketAddr::new(IpAddr::V4(ip), port),
                noise_pub: [2u8; 32],
                ed25519_pub: [3u8; 32],
                last_seen: i as i64 + 1,
                failed_queries: 0,
            },
        );
    }
    assert_eq!(map.len(), 2);
    assert!(
        !map.contains_key(&(ip, 4672)),
        "the oldest extra port is dropped"
    );
    assert!(map.contains_key(&(ip, 4673)));
    assert!(map.contains_key(&(ip, 4674)));
}

fn test_ember_contact(id_byte: u8, ip: [u8; 4], port: u16) -> ember::dht::EmberContact {
    ember::dht::EmberContact {
        node_id: ember::dht::EmberNodeId([id_byte; 16]),
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port),
        noise_pub: [id_byte; 32],
        ed25519_pub: [id_byte.wrapping_add(1); 32],
        last_seen: 1,
        failed_queries: 0,
    }
}

#[test]
fn announce_targets_include_a_session_only_friend() {
    let friend = test_ember_contact(1, [192, 168, 1, 10], 4672);
    let mut session = HashMap::new();
    session.insert((Ipv4Addr::new(192, 168, 1, 10), 4672), friend.clone());
    let announced = HashMap::new();
    let local = ember::dht::EmberNodeId([0xFF; 16]);
    let targets =
        ember_dht_announce_targets(Vec::new(), &session, &announced, local, 8);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].node_id, friend.node_id);
}

#[test]
fn announce_targets_are_least_recent_first_and_honour_the_budget() {
    let a = test_ember_contact(1, [8, 8, 8, 8], 4672);
    let b = test_ember_contact(2, [1, 1, 1, 1], 4672);
    let table = vec![a.clone(), b.clone()];
    let session = HashMap::new();
    let mut announced = HashMap::new();
    announced.insert(a.node_id, 990);
    announced.insert(b.node_id, 100);
    let local = ember::dht::EmberNodeId([0xFF; 16]);
    let targets = ember_dht_announce_targets(table, &session, &announced, local, 1);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].node_id, b.node_id, "least recently announced");
}

/// A peer that spoke to us while its liveness PING was outstanding has
/// proven it is alive, whatever message type it used. Only the PONG's own
/// request id clears the pending entry, so before this a contact answering
/// FIND_NODE or gossiping a PEER_LIST still collected a strike every time,
/// and three of them evicted a working peer.
#[test]
fn a_contact_heard_from_since_the_ping_is_not_faulted() {
    assert!(
        !ember_ping_timeout_is_a_fault(Some(1_050), 1_000),
        "answered something else after we asked"
    );
    assert!(
        !ember_ping_timeout_is_a_fault(Some(1_000), 1_000),
        "same second counts as heard"
    );
    assert!(
        ember_ping_timeout_is_a_fault(Some(900), 1_000),
        "silent since the ping went out"
    );
    assert!(
        ember_ping_timeout_is_a_fault(Some(0), 1_000),
        "an unverified lead that never answered is still a fault"
    );
    assert!(
        !ember_ping_timeout_is_a_fault(None, 1_000),
        "contact already gone: nothing to charge"
    );
}

/// A ping still queued behind a Noise handshake has not been transmitted,
/// so it must not be judged on the on-the-wire budget.
#[test]
fn a_queued_ping_gets_the_longer_deadline() {
    let node = ember::dht::EmberNodeId([3; 16]);
    let before = std::time::Instant::now();
    let direct = new_ember_maint_ping(node, false, 1_000);
    let queued = new_ember_maint_ping(node, true, 1_000);
    assert!(queued.deadline > direct.deadline);
    assert!(direct.deadline >= before + EMBER_MAINT_PING_TIMEOUT);
    assert!(queued.deadline >= before + EMBER_MAINT_PING_QUEUED_TIMEOUT);
    assert_eq!(direct.sent_unix, 1_000);
    assert_eq!(queued.node_id, node);
}

/// The sweep runs on the announce interval, so a tick that fires a moment
/// early must still announce. Filtering on "announced within the interval"
/// here silently skipped the only peer a one-contact table had.
#[test]
fn a_recently_announced_contact_is_still_offered_when_it_is_all_we_have() {
    let only = test_ember_contact(1, [8, 8, 8, 8], 4672);
    let mut announced = HashMap::new();
    announced.insert(only.node_id, 999);
    let targets = ember_dht_announce_targets(
        vec![only.clone()],
        &HashMap::new(),
        &announced,
        ember::dht::EmberNodeId([0xFF; 16]),
        8,
    );
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].node_id, only.node_id);
}

#[test]
fn announce_gossip_shares_session_contacts_only_with_lan_peers() {
    let lan_peer = test_ember_contact(1, [192, 168, 1, 10], 4672);
    let public_peer = test_ember_contact(2, [8, 8, 8, 8], 4672);
    let extra = test_ember_contact(3, [192, 168, 1, 20], 4672);
    let mut session = HashMap::new();
    session.insert((Ipv4Addr::new(192, 168, 1, 20), 4672), extra.clone());
    let local = ember::dht::EmberNodeId([0xFF; 16]);

    let to_lan = ember_announce_gossip(Vec::new(), &session, &lan_peer, local);
    assert!(to_lan.iter().any(|c| c.node_id == extra.node_id));

    let to_public = ember_announce_gossip(Vec::new(), &session, &public_peer, local);
    assert!(
        to_public.is_empty(),
        "LAN session contacts must not be gossiped to the public net"
    );
}

/// A friend asks for contacts because its own table is thin, so answering
/// with addresses we have never heard from would hand it our guesses and
/// call them introductions. `find_closest` falls back to leads exactly
/// when we hold nothing verified, which is the case that must answer
/// empty instead.
#[test]
fn a_friend_is_only_ever_told_about_contacts_that_answered_us() {
    let target = ember::dht::EmberNodeId([0x11; 16]);
    let mut table =
        ember::dht::routing::RoutingTable::new(ember::dht::EmberNodeId([0xFF; 16]), false);

    let mut lead = test_ember_contact(2, [10, 2, 0, 20], 4672);
    lead.last_seen = 0;
    table.add_contact(lead.clone());
    assert!(!lead.is_verified());
    assert!(
        ember_friend_contact_answer(&table, &target).is_empty(),
        "a node holding only leads has nothing to introduce"
    );

    let proven = test_ember_contact(1, [10, 1, 0, 10], 4672);
    assert!(proven.is_verified());
    table.add_contact(proven.clone());
    let answer = ember_friend_contact_answer(&table, &target);
    assert_eq!(answer.len(), 1);
    assert_eq!(answer[0].node_id, proven.node_id);
}

/// Every friend has to get a turn. The ask interval equals the maintenance
/// tick, so a friend asked last cycle is due again this cycle, and the
/// per-tick budget is smaller than a friends list — so ordering by
/// least-recently-asked is the only thing stopping the first few from
/// holding the budget while the rest are never asked at all.
#[test]
fn the_friend_ask_rotates_instead_of_pinning_the_first_few() {
    let friends: Vec<[u8; 16]> = (1..=9u8).map(|i| [i; 16]).collect();
    assert!(
        friends.len() > EMBER_FRIEND_CONTACT_ASKS_PER_TICK,
        "the fixture only means anything with more friends than one tick can ask"
    );
    let mut asked: HashMap<[u8; 16], std::time::Instant> = HashMap::new();
    let mut ever_asked: HashSet<[u8; 16]> = HashSet::new();
    let start = std::time::Instant::now();

    for tick in 0..3u32 {
        let now = start + EMBER_FRIEND_CONTACT_ASK_INTERVAL * tick;
        let live: Vec<([u8; 16], ())> = friends.iter().map(|f| (*f, ())).collect();
        let due = ember_friend_ask_order(live, &asked, now);
        for (eh, _) in due.into_iter().take(EMBER_FRIEND_CONTACT_ASKS_PER_TICK) {
            asked.insert(eh, now);
            ever_asked.insert(eh);
        }
    }

    assert_eq!(
        ever_asked.len(),
        friends.len(),
        "every friend must get a turn within a few ticks"
    );
}

/// A friend asked this tick must not be asked again on the next one, or
/// the throttle would be doing nothing.
#[test]
fn a_friend_just_asked_is_not_due_again_immediately() {
    let friend = [7u8; 16];
    let start = std::time::Instant::now();
    let mut asked = HashMap::new();
    asked.insert(friend, start);

    let soon = start + EMBER_FRIEND_CONTACT_ASK_INTERVAL / 2;
    assert!(ember_friend_ask_order(vec![(friend, ())], &asked, soon).is_empty());

    let later = start + EMBER_FRIEND_CONTACT_ASK_INTERVAL;
    assert_eq!(
        ember_friend_ask_order(vec![(friend, ())], &asked, later).len(),
        1
    );
}

/// A contact with a real key, since the friend answer is decoded on the
/// far side and `decode_contact_list` drops anything whose Ed25519 key is
/// not a valid point.
fn keyed_ember_contact(seed: u8, ip: [u8; 4]) -> ember::dht::EmberContact {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let vk = sk.verifying_key();
    ember::dht::EmberContact {
        node_id: ember::dht::EmberNodeId(
            crate::network::ember::crypto::node_id_from_public_key(&vk),
        ),
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), 4672),
        noise_pub: [seed; 32],
        ed25519_pub: vk.to_bytes(),
        last_seen: 1,
        failed_queries: 0,
    }
}

/// What we hand a friend has to survive the round trip the friend session
/// puts it through, and arrive on the far side as *leads* — with every
/// node ID re-derived from the key beside it, so a friend cannot name a
/// contact under an ID it does not control.
#[test]
fn a_friend_answer_survives_the_round_trip_as_unverified_leads() {
    let target = ember::dht::EmberNodeId([0x11; 16]);
    let mut table =
        ember::dht::routing::RoutingTable::new(ember::dht::EmberNodeId([0xFF; 16]), false);
    // Distinct /24s, or the diversity caps refuse most of them.
    for i in 1..=ember::dht::MAX_CONTACTS_PER_RESPONSE as u8 {
        table.add_contact(keyed_ember_contact(i, [10, 0, i, 10]));
    }
    let answer = ember_friend_contact_answer(&table, &target);
    assert!(!answer.is_empty(), "the fixture must produce an answer");

    let body = ember::dht::messages::encode_contact_list(&answer);
    let frame =
        ed2k::messages::build_ember_ext_frame(ed2k::messages::EMBER_EXT_DHT_CONTACTS, &body);
    let (ext_type, wire_body) =
        ed2k::messages::parse_ember_ext(&frame[6..]).expect("a framed answer parses");
    assert_eq!(ext_type, ed2k::messages::EMBER_EXT_DHT_CONTACTS);
    assert!(
        wire_body.len() <= ember::dht::messages::MAX_CONTACT_LIST_BYTES,
        "the receiver refuses a body over the cap before decoding it, so an \
         honest answer must fit: {} contacts encoded to {} bytes",
        answer.len(),
        wire_body.len()
    );

    // The encoder trims to its own datagram budget, which over TCP only
    // caps the answer at 17 — see `encode_contact_list`. What must hold is
    // that nothing it did carry is lost on the far side.
    let carried = wire_body[0] as usize;
    assert!(carried > 0 && carried <= answer.len());
    let decoded = ember::dht::messages::decode_contact_list(wire_body)
        .expect("our own answer must decode");
    assert_eq!(
        decoded.len(),
        carried,
        "no carried contact may be dropped for an unusable key"
    );
    for contact in &decoded {
        assert_eq!(
            contact.node_id.0,
            crate::network::ember::crypto::node_id_from_ed25519_bytes(&contact.ed25519_pub)
                .expect("the fixture keys are valid points"),
            "the ID must come from the key, never from the wire"
        );
        assert!(
            !contact.is_verified(),
            "a contact learned from a friend is a lead until it answers us"
        );
    }
}

#[test]
fn record_ember_noise_key_evicts_oldest_at_capacity() {
    let mut map = HashMap::new();
    // Fill to the cap with sequentially-aged entries so the first
    // insert is the oldest by timestamp.
    for i in 0..MAX_KNOWN_EMBER_NOISE_KEYS {
        let i16 = i as u16;
        let ip = Ipv4Addr::new(10, 0, (i16 >> 8) as u8, (i16 & 0xFF) as u8);
        let mut key = [0u8; 32];
        key[0] = (i & 0xFF) as u8;
        assert_eq!(record_ember_noise_key(&mut map, ip, 4662, key), None);
        std::thread::sleep(std::time::Duration::from_micros(50));
    }
    let oldest = (Ipv4Addr::new(10, 0, 0, 0), 4662u16);
    assert!(map.contains_key(&oldest));
    assert_eq!(map.len(), MAX_KNOWN_EMBER_NOISE_KEYS);

    // Inserting one more brand-new address must evict the oldest.
    let newcomer = (Ipv4Addr::new(11, 0, 0, 1), 4662u16);
    let mut key = [0u8; 32];
    key[31] = 0xFF;
    assert_eq!(
        record_ember_noise_key(&mut map, newcomer.0, newcomer.1, key),
        None
    );
    assert_eq!(map.len(), MAX_KNOWN_EMBER_NOISE_KEYS);
    assert!(!map.contains_key(&oldest));
    assert!(map.contains_key(&newcomer));
}

#[test]
fn lookup_ember_noise_key_respects_ttl() {
    // Forward-shift the comparison clock instead of backdating the
    // timestamps. Backdating with `Instant::checked_sub(TTL + 60s)`
    // returns `None` on Windows when the system has been up for
    // less than the TTL (the monotonic counter origin is too
    // young), which used to make this test panic with
    // "clock supports a backdated Instant" in fresh CI containers.
    let mut map = HashMap::new();
    let fresh_ip = Ipv4Addr::new(1, 2, 3, 4);
    let stale_ip = Ipv4Addr::new(5, 6, 7, 8);
    let port = 4662u16;

    let stale_ts = std::time::Instant::now();
    // `now` is one minute past the TTL boundary measured from
    // `stale_ts`, so `now - stale_ts == TTL + 60s` (clearly stale)
    // and `now - fresh_ts == 60s` (clearly fresh, comfortably under
    // TTL with both the lookup and prune comparisons being strict
    // less-than).
    let now = stale_ts + KNOWN_EMBER_PEER_TTL + std::time::Duration::from_secs(60);
    let fresh_ts = now
        .checked_sub(std::time::Duration::from_secs(60))
        .expect("synthetic test instant is advanced enough");

    let key_fresh = [0x11u8; 32];
    let key_stale = [0x22u8; 32];

    map.insert((fresh_ip, port), (key_fresh, fresh_ts));
    map.insert((stale_ip, port), (key_stale, stale_ts));

    assert_eq!(
        lookup_ember_noise_key_at(&map, fresh_ip, port, now),
        Some(key_fresh)
    );
    // Stale entry is hidden from lookups even before the prune sweep.
    assert_eq!(lookup_ember_noise_key_at(&map, stale_ip, port, now), None);

    // Prune sweep evicts the stale entry from the map itself.
    prune_stale_ember_noise_keys_at(&mut map, now);
    assert!(map.contains_key(&(fresh_ip, port)));
    assert!(!map.contains_key(&(stale_ip, port)));
}

/// Round-trip from publish-side blob tag → wire bytes →
/// `extract_kad_sources` consumer. Confirms the tag we emit in
/// `build_source_publish` is exactly what `extract_kad_sources`
/// reads back, without manually building a hand-crafted entry.
#[test]
fn extract_kad_sources_round_trip_picks_up_noise_pubkey() {
    use crate::network::kad::messages::SearchResultEntry;
    use crate::network::kad::publish::{EMBER_CAP_RELAY_PUNCH_V1, EMBER_NOISE_PUB_TAG};
    use crate::network::kad::types::{
        KadId, KadTag, TagName, TagValue, TAG_SOURCEIP, TAG_SOURCEPORT, TAG_SOURCETYPE,
    };

    let mut npub = [0u8; 32];
    for (i, b) in npub.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }

    let entry = SearchResultEntry {
        id: KadId([0; 16]),
        tags: vec![
            KadTag {
                name: TagName::Id(TAG_SOURCEIP),
                value: TagValue::Uint32(u32::from(Ipv4Addr::new(80, 1, 2, 3)).to_be()),
            },
            KadTag {
                name: TagName::Id(TAG_SOURCEPORT),
                value: TagValue::Uint16(4662),
            },
            KadTag {
                name: TagName::Id(TAG_SOURCETYPE),
                value: TagValue::Uint8(1),
            },
            KadTag {
                name: TagName::Str("ember".to_string()),
                value: TagValue::Uint8(EMBER_CAP_RELAY_PUNCH_V1),
            },
            KadTag {
                name: TagName::Str(EMBER_NOISE_PUB_TAG.to_string()),
                value: TagValue::Blob(npub.to_vec()),
            },
        ],
    };

    let sources = extract_kad_sources(&[entry]);
    assert_eq!(sources.len(), 1);
    assert!(sources[0].is_ember_capable);
    assert_eq!(sources[0].ember_noise_pub, Some(npub));
}

/// Wrong-length and all-zero Noise pubkey blobs must be rejected
/// at extract time so the cache cannot be poisoned with a key
/// that no one can ever decrypt under.
#[test]
fn extract_kad_sources_rejects_invalid_noise_pubkey_blobs() {
    use crate::network::kad::messages::SearchResultEntry;
    use crate::network::kad::publish::EMBER_NOISE_PUB_TAG;
    use crate::network::kad::types::{
        KadId, KadTag, TagName, TagValue, TAG_SOURCEIP, TAG_SOURCEPORT, TAG_SOURCETYPE,
    };

    let make_entry = |blob: Vec<u8>| SearchResultEntry {
        id: KadId([0; 16]),
        tags: vec![
            KadTag {
                name: TagName::Id(TAG_SOURCEIP),
                value: TagValue::Uint32(u32::from(Ipv4Addr::new(80, 1, 2, 3)).to_be()),
            },
            KadTag {
                name: TagName::Id(TAG_SOURCEPORT),
                value: TagValue::Uint16(4662),
            },
            KadTag {
                name: TagName::Id(TAG_SOURCETYPE),
                value: TagValue::Uint8(1),
            },
            KadTag {
                name: TagName::Str(EMBER_NOISE_PUB_TAG.to_string()),
                value: TagValue::Blob(blob),
            },
        ],
    };

    // 31 bytes (truncated)
    let sources = extract_kad_sources(&[make_entry(vec![0x42u8; 31])]);
    assert_eq!(sources[0].ember_noise_pub, None);

    // 33 bytes (overlong)
    let sources = extract_kad_sources(&[make_entry(vec![0x42u8; 33])]);
    assert_eq!(sources[0].ember_noise_pub, None);

    // All-zero (matches the publish-side suppression sentinel)
    let sources = extract_kad_sources(&[make_entry(vec![0u8; 32])]);
    assert_eq!(sources[0].ember_noise_pub, None);
}

#[test]
fn prune_stale_ember_peers_drops_expired_entries() {
    // Same forward-shift trick as `lookup_ember_noise_key_respects_ttl`:
    // pin the "stale" timestamp at `Instant::now()` and call the
    // `_at` variant with a synthetic `now` advanced past the TTL.
    // Backdating `Instant` with `checked_sub` is unreliable on
    // Windows / freshly-booted systems where the monotonic clock
    // reference is younger than `KNOWN_EMBER_PEER_TTL`.
    let mut map = HashMap::new();
    let fresh_ip = Ipv4Addr::new(1, 2, 3, 4);
    let stale_ip = Ipv4Addr::new(5, 6, 7, 8);
    let stale_ts = std::time::Instant::now();
    // `now - stale_ts == TTL + 60s` (stale), `now - fresh_ts == 60s`
    // (fresh under the strict less-than comparison in `prune`).
    let now = stale_ts + KNOWN_EMBER_PEER_TTL + std::time::Duration::from_secs(60);
    let fresh_ts = now
        .checked_sub(std::time::Duration::from_secs(60))
        .expect("synthetic test instant is advanced enough");

    map.insert((fresh_ip, 4662), fresh_ts);
    map.insert((stale_ip, 4662), stale_ts);

    prune_stale_ember_peers_at(&mut map, now);
    assert!(map.contains_key(&(fresh_ip, 4662)));
    assert!(!map.contains_key(&(stale_ip, 4662)));
}

#[test]
fn ident_state_label_covers_every_variant() {
    // Lock the UI labels for the upload-pane Queued / Known Clients
    // tabs against accidental rename. eMule users recognise these
    // exact strings from the Identification row of their own client
    // details dialog.
    use ed2k::credits::IdentState;
    assert_eq!(ident_state_label(IdentState::Verified), "Verified");
    assert_eq!(ident_state_label(IdentState::Failed), "Failed");
    assert_eq!(ident_state_label(IdentState::BadGuy), "BadGuy");
    assert_eq!(ident_state_label(IdentState::Needed), "Needed");
    assert_eq!(ident_state_label(IdentState::Unknown), "Unknown");
    // Sanity: the lowercased form drives the `ident-*` CSS classes
    // in the transfers page; a label that lower-cases to a class
    // we don't have CSS for is rendered with the default text colour.
    for label in [
        ident_state_label(IdentState::Verified),
        ident_state_label(IdentState::Failed),
        ident_state_label(IdentState::BadGuy),
        ident_state_label(IdentState::Needed),
        ident_state_label(IdentState::Unknown),
    ] {
        assert!(
            label.chars().all(|c| c.is_ascii_alphanumeric()),
            "label {label} contains non-alphanumeric chars (would break ident-* class lookup)"
        );
    }
}

#[test]
fn note_results_keep_requested_file_hash() {
    let file_hash = KadId([0x11; 16]);
    let publisher = KadId([0x22; 16]);
    let entries = vec![SearchResultEntry {
        id: publisher,
        tags: vec![
            KadTag {
                name: TagName::Id(TAG_FILENAME),
                value: TagValue::String("example.bin".to_string()),
            },
            KadTag {
                name: TagName::Id(TAG_FILERATING),
                value: TagValue::Uint8(5),
            },
            KadTag {
                name: TagName::Id(TAG_DESCRIPTION),
                value: TagValue::String("Looks good".to_string()),
            },
        ],
    }];

    let results = convert_note_search_results(&entries, &file_hash);

    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].file.hash,
        hex::encode(kad_id_to_md4_bytes(&file_hash))
    );
    assert_eq!(results[0].peer_id, publisher.to_hex());
    assert_eq!(results[0].comment.as_deref(), Some("Looks good"));
    assert_eq!(results[0].rating, Some(5));
}

#[test]
fn search_results_extract_kad_media_tags() {
    let entries = vec![SearchResultEntry {
        id: KadId([0x44; 16]),
        tags: vec![
            KadTag {
                name: TagName::Id(TAG_FILENAME),
                value: TagValue::String("track.mp3".to_string()),
            },
            KadTag {
                name: TagName::Id(TAG_FILESIZE),
                value: TagValue::Uint32(4_000_000),
            },
            KadTag {
                name: TagName::Id(TAG_MEDIA_ARTIST),
                value: TagValue::String("Some Artist".to_string()),
            },
            KadTag {
                name: TagName::Id(TAG_MEDIA_ALBUM),
                value: TagValue::String("Some Album".to_string()),
            },
            KadTag {
                name: TagName::Id(TAG_MEDIA_TITLE),
                value: TagValue::String("Some Title".to_string()),
            },
            KadTag {
                name: TagName::Id(TAG_MEDIA_LENGTH),
                value: TagValue::Uint32(225),
            },
            KadTag {
                name: TagName::Id(TAG_MEDIA_BITRATE),
                value: TagValue::Uint32(320),
            },
            KadTag {
                name: TagName::Id(TAG_MEDIA_CODEC),
                value: TagValue::String("mp3".to_string()),
            },
        ],
    }];

    let results = convert_search_results(&entries, |_| true);
    assert_eq!(results.len(), 1);
    let media = results[0].media.as_ref().expect("media present");
    assert_eq!(media.artist.as_deref(), Some("Some Artist"));
    assert_eq!(media.album.as_deref(), Some("Some Album"));
    assert_eq!(media.title.as_deref(), Some("Some Title"));
    assert_eq!(media.duration, Some(225));
    assert_eq!(media.bitrate, Some(320));
    assert_eq!(media.codec.as_deref(), Some("mp3"));
}

#[test]
fn search_results_without_media_leave_field_none() {
    let entries = vec![SearchResultEntry {
        id: KadId([0x55; 16]),
        tags: vec![
            KadTag {
                name: TagName::Id(TAG_FILENAME),
                value: TagValue::String("doc.pdf".to_string()),
            },
            KadTag {
                name: TagName::Id(TAG_FILESIZE),
                value: TagValue::Uint32(1234),
            },
        ],
    }];
    let results = convert_search_results(&entries, |_| true);
    assert_eq!(results.len(), 1);
    assert!(results[0].media.is_none());
}

/// Both Kad counts are estimates of one swarm, so neither accumulates with
/// the number of nodes that answered. eMule branches on `m_bKademlia` in
/// `AddSources` and `AddCompleteSources` alike and keeps the larger value.
#[test]
fn kad_source_counts_take_max_across_publishers() {
    use crate::network::kad::types::{TAG_COMPLETE_SOURCES, TAG_FILESIZE, TAG_SOURCES};
    let file_id = KadId([0x66; 16]);
    let entry = |complete: u32, sources: u32| SearchResultEntry {
        id: file_id,
        tags: vec![
            KadTag {
                name: TagName::Id(TAG_FILENAME),
                value: TagValue::String("movie.mkv".to_string()),
            },
            KadTag {
                name: TagName::Id(TAG_FILESIZE),
                value: TagValue::Uint32(1_000),
            },
            KadTag {
                name: TagName::Id(TAG_SOURCES),
                value: TagValue::Uint32(sources),
            },
            KadTag {
                name: TagName::Id(TAG_COMPLETE_SOURCES),
                value: TagValue::Uint32(complete),
            },
        ],
    };
    let results = convert_search_results(&[entry(50, 10), entry(80, 10)], |_| true);
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].file.complete_sources, 80,
        "swarm estimates must not sum"
    );
    assert_eq!(
        results[0].availability, 10,
        "two nodes describing the same ten sources are still ten sources"
    );
    assert!(
        results[0].availability >= results[0].file.complete_sources
            || !crate::search::merge::complete_sources_known(&results[0].result_origin),
        "a Kad row may report more complete sources than sources, which is \
         exactly why its complete count is not shown as a known figure"
    );
}

#[test]
fn kad_search_omits_port_zero_source_addresses() {
    use crate::network::kad::types::{TAG_FILESIZE, TAG_SOURCEIP, TAG_SOURCEPORT};
    let entries = vec![SearchResultEntry {
        id: KadId([0x77; 16]),
        tags: vec![
            KadTag {
                name: TagName::Id(TAG_FILENAME),
                value: TagValue::String("a.bin".to_string()),
            },
            KadTag {
                name: TagName::Id(TAG_FILESIZE),
                value: TagValue::Uint32(1),
            },
            KadTag {
                name: TagName::Id(TAG_SOURCEIP),
                value: TagValue::Uint32(u32::from_be_bytes([8, 8, 8, 8])),
            },
            KadTag {
                name: TagName::Id(TAG_SOURCEPORT),
                value: TagValue::Uint16(0),
            },
        ],
    }];
    let results = convert_search_results(&entries, |_| true);
    assert_eq!(results.len(), 1);
    assert!(
        results[0].source_addresses.is_empty(),
        "port 0 is not a connectable search source"
    );
}

/// `extract_kad_sources` must read the `"ember"` capability tag we
/// emit in `kad/publish.rs::build_source_publish` and surface it as
/// `is_ember_capable`. This is the linchpin of the broker dispatch
/// gate — if parsing breaks, every Ember peer silently regresses
/// to "skip broker" and LowID-to-LowID becomes unreachable.
#[test]
fn extract_kad_sources_reads_ember_capability_tag() {
    use crate::network::kad::publish::EMBER_CAP_RELAY_PUNCH_V1;
    use crate::network::kad::types::{
        TAG_ENCRYPTION, TAG_FILESIZE, TAG_SOURCEIP, TAG_SOURCEPORT, TAG_SOURCETYPE,
    };

    // Ember-capable HighID source.
    let ember_entry = SearchResultEntry {
        id: KadId([0x33; 16]),
        tags: vec![
            KadTag {
                name: TagName::Id(TAG_SOURCEIP),
                // 1.2.3.4 in network byte order -> u32(0x01020304)
                value: TagValue::Uint32(u32::from_be_bytes([1, 2, 3, 4])),
            },
            KadTag {
                name: TagName::Id(TAG_SOURCEPORT),
                value: TagValue::Uint16(4662),
            },
            KadTag {
                name: TagName::Id(TAG_SOURCETYPE),
                value: TagValue::Uint8(1),
            },
            KadTag {
                name: TagName::Id(TAG_FILESIZE),
                value: TagValue::Uint64(123),
            },
            KadTag {
                name: TagName::Id(TAG_ENCRYPTION),
                value: TagValue::Uint8(0),
            },
            KadTag {
                name: TagName::Str("ember".to_string()),
                value: TagValue::Uint8(EMBER_CAP_RELAY_PUNCH_V1),
            },
        ],
    };

    // Vanilla eMule source — no `"ember"` tag.
    let emule_entry = SearchResultEntry {
        id: KadId([0x44; 16]),
        tags: vec![
            KadTag {
                name: TagName::Id(TAG_SOURCEIP),
                value: TagValue::Uint32(u32::from_be_bytes([5, 6, 7, 8])),
            },
            KadTag {
                name: TagName::Id(TAG_SOURCEPORT),
                value: TagValue::Uint16(4663),
            },
            KadTag {
                name: TagName::Id(TAG_SOURCETYPE),
                value: TagValue::Uint8(1),
            },
        ],
    };

    let sources = extract_kad_sources(&[ember_entry, emule_entry]);
    assert_eq!(sources.len(), 2);

    let ember_src = sources
        .iter()
        .find(|s| s.tcp_port == 4662)
        .expect("ember source should be present");
    assert!(
        ember_src.is_ember_capable,
        "source carrying `ember` tag must be marked ember-capable",
    );

    let emule_src = sources
        .iter()
        .find(|s| s.tcp_port == 4663)
        .expect("emule source should be present");
    assert!(
        !emule_src.is_ember_capable,
        "source without `ember` tag must default to NOT ember-capable — \
         this is what guards the broker against wasting cycles on vanilla eMule",
    );
}
