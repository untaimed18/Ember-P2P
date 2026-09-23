//! The Ember DHT background health loop: routine maintenance while there is
//! work, bridging from KAD, and rendezvous lookups for other Ember nodes.

use super::*;

pub(in crate::network) async fn on_ember_maintenance_tick(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    settings: &AppSettings,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    identity: &Arc<crate::storage::identity::NodeIdentity>,
) {
    // Background health loop. `force = false`: honour the
    // staleness gates so steady-state churn stays low.
    //
    // Run when there are contacts to maintain, or when the table is
    // empty but we hold something the bridge could bootstrap from —
    // Ember peers learned from KAD source tags (dialed over Noise_IK)
    // or from eD2K sessions (dialed over Noise_XX). An idle node with
    // nothing to work with stays quiet.
    //
    // The remembered address book counts as work on its own. Every
    // other condition here is live state, and all of it is
    // perishable: contacts fault out after three missed pings,
    // `ember_noise_keys` expires on `KNOWN_EMBER_PEER_TTL`, keyless
    // peers and friend sessions go with their eD2K sessions. A
    // suspend/resume, an interface or VPN change, an `ipfilter.dat`
    // reload or simply a long stretch offline can empty all of them
    // together — and then the one thing that could still get us
    // back, the book on disk, was unreachable, because the top-up
    // that offers it and the `rearm_offers` that makes a spent book
    // offerable again both run *inside* this cycle. Nothing outside
    // it can add a contact when no peer knows us and the eD2K side
    // is quiet too, so the node stayed dark until it was restarted.
    // That is the restart-only ratchet `peer_cache` exists to break.
    let mut ember_has_work = state.ember_dht.contact_count() > 0
        || !state.ember_session_dht_contacts.is_empty()
        || !state.ember_noise_keys.is_empty()
        || !state.ember_keyless_peers.is_empty()
        || state.ember_bootstrap_cache.remembered_len() > 0;
    // A live friend session counts on its own. It is the one
    // bootstrap path that needs no dialable address for the peer
    // introducing us, so the node it matters most to — a cold join
    // whose only peer is a friend behind a relayed session — has
    // every condition above empty. Without this the friend ask
    // could never fire in the case it exists for. Read last, so the
    // lock is only taken when the cheap checks all missed.
    if settings.ember_native_enabled && !ember_has_work {
        ember_has_work = state
            .ember_sessions
            .read()
            .await
            .values()
            .any(|h| h.is_fresh() && h.is_secure_v2());
    }
    if settings.ember_native_enabled && ember_has_work {
        let _ = run_ember_maintenance(udp_socket, state, false).await;
        maybe_publish_channel_presence(
            udp_socket,
            state,
            db,
            settings,
            identity,
        )
        .await;
        publish_channel_departures(
            udp_socket,
            state,
            db,
            settings,
            identity,
        )
        .await;
        maybe_publish_owned_channel_records(
            udp_socket,
            state,
            db,
            settings,
            identity,
        )
        .await;
    }
    if settings.ember_native_enabled {
        // Release per-author flood slots for members who have gone
        // quiet. Without this the map fills in a busy room and then
        // refuses newcomers, since an untracked author has to be
        // refused rather than waved through.
        ember::channel::prune_rate_windows(
            &mut state.channel_gossip_author_times,
            std::time::Instant::now(),
            std::time::Duration::from_secs(60),
        );
        // Same reclaim for the catch-up budget: its entries only
        // mean anything for a minute, and holding them past that
        // fills the map with requesters who asked once and left.
        ember::channel::prune_rate_windows(
            &mut state.channel_history_sync_times,
            std::time::Instant::now(),
            std::time::Duration::from_secs(60),
        );
        // And the hop admission map, which was the one being
        // missed. It refuses any unseen hop once
        // `CHANNEL_GOSSIP_IN_PEER_CAP` slots are held, and DHT
        // churn alone fills it, so without this sweep a long
        // session quietly stopped accepting channel traffic from
        // anyone it had not already spoken to until the next
        // restart.
        ember::channel::prune_rate_windows(
            &mut state.channel_gossip_from_times,
            std::time::Instant::now(),
            std::time::Duration::from_secs(60),
        );
        maybe_refresh_channel_moderation(udp_socket, state, db, settings)
            .await;
        maybe_refresh_channel_handoff(udp_socket, state, db, settings)
            .await;
        maybe_refresh_channel_key_epoch(
            udp_socket,
            state,
            db,
            settings,
            identity,
        )
        .await;
    }

    // Nothing to bridge from means nobody has crossed our path yet.
    // Ask KAD directly for other Ember nodes. The 1 Hz search timer
    // drives the same helper until the first lookup starts, because
    // this tick cannot: its first evaluation is too early for KAD to
    // be up and its second is a minute later.
    maybe_start_ember_rendezvous_lookup(
        state,
        app_handle,
        settings.ember_native_enabled,
    );
}
